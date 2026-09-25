"""Chargement et validation de config/hosts.yaml et config/policies.yaml."""

from __future__ import annotations

import ntpath
import os
import posixpath
import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, field_validator, model_validator

LEVELS = ("read", "dev", "admin")
MODE_LEVELS = {"safe": {"read"}, "dev": {"read", "dev"}, "admin": {"read", "dev", "admin"}}

_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]*$")
_GLOB_RE = re.compile(r"^[A-Za-z0-9._*?\- ]+$")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProjectConfig(_Strict):
    path: str
    test: str | None = None
    build: str | None = None


class DockerConfig(_Strict):
    enabled: bool = False
    # Vide : docker_logs autorisé sur tous les conteneurs, docker_restart interdit.
    # Non vide : logs et restart limités à cette liste.
    allowed_containers: list[str] = Field(default_factory=list)
    # docker_compose_up refuse par défaut les services privilégiés, pid/network host,
    # cap_add, devices et les bind mounts hors allowed_paths.
    allow_unsafe_compose: bool = False


class ServicesConfig(_Strict):
    restartable: list[str] = Field(default_factory=list)
    # linux : "user" -> systemctl --user ; "sudo" -> sudo -n systemctl (règle sudoers requise)
    restart_mode: Literal["user", "sudo"] = "user"

    @field_validator("restartable")
    @classmethod
    def _names(cls, v: list[str]) -> list[str]:
        for name in v:
            if not _NAME_RE.match(name):
                raise ValueError(f"nom de service invalide : {name!r}")
        return v


class WinRMConfig(_Strict):
    use_ssl: bool = False
    port: int | None = None
    authentication: str | None = None  # Default, Kerberos, Negotiate...
    configuration_name: str | None = None  # endpoint JEA recommandé


class HostConfig(_Strict):
    name: str = ""
    os: Literal["linux", "windows"]
    backend: Literal["ssh", "winrm", "powershell", "local"]
    host: str | None = None
    user: str | None = None
    port: int | None = None
    key: str | None = None
    ssh_alias: str | None = None
    # default : clé SSH (ssh) / compte Windows courant (winrm).
    # password : identifiant `user` + mot de passe chiffré dans config/credentials.dat.
    auth: Literal["default", "password"] = "default"
    # SSH vers Windows : PowerShell lancé sur la cible (pwsh = 7, powershell = 5.1 intégré).
    ps_exe: Literal["pwsh", "powershell"] = "pwsh"
    # Forcé à "powershell" pour Windows ; surchargeable pour les tests (pwsh sous Linux).
    shell: Literal["posix", "powershell"] | None = None
    permissions: list[Literal["read", "dev", "admin"]] = Field(default_factory=lambda: ["read"])
    allowed_paths: list[str]
    projects: dict[str, ProjectConfig] = Field(default_factory=dict)
    docker: DockerConfig = Field(default_factory=DockerConfig)
    services: ServicesConfig = Field(default_factory=ServicesConfig)
    log_sources: dict[str, str] = Field(default_factory=dict)
    # Dossiers ajoutés en tête du PATH (ex. node installé via nvm, absent des sessions SSH non interactives).
    path_prepend: list[str] = Field(default_factory=list)
    winrm: WinRMConfig = Field(default_factory=WinRMConfig)
    # Dossier de config d'origine (pour retrouver credentials.dat) ; renseigné par load_config.
    _config_dir: Path | None = PrivateAttr(default=None)

    def password_blob(self) -> bytes:
        """Mot de passe chiffré (DPAPI) de cette machine ; erreur claire s'il manque."""
        from . import credentials

        blob = credentials.blob(self.name, self._config_dir)
        if not blob:
            raise RuntimeError(f"aucun mot de passe enregistré pour {self.name!r} (le saisir dans l'interface)")
        return blob

    @model_validator(mode="after")
    def _normalize(self) -> "HostConfig":
        if self.backend == "powershell":
            self.backend = "winrm"
        if self.shell is None:
            self.shell = "powershell" if self.os == "windows" else "posix"
        if self.os == "windows" and self.shell != "powershell":
            raise ValueError("un hôte windows utilise forcément le shell powershell")
        if self.backend == "winrm" and self.shell != "powershell":
            raise ValueError("le backend winrm exige le shell powershell")
        if self.backend in ("ssh", "winrm") and not (self.host or self.ssh_alias):
            raise ValueError("'host' ou 'ssh_alias' requis")
        if self.auth == "password":
            if self.backend == "local":
                raise ValueError("pas de mot de passe pour le backend local")
            if not self.user and not (self.backend == "ssh" and self.ssh_alias):
                raise ValueError("un identifiant (user) est requis avec un mot de passe")
        for value in (self.host, self.ssh_alias):
            if value is not None and not _HOST_RE.match(value):
                raise ValueError(f"nom d'hôte invalide : {value!r}")
        if self.user is not None and not _NAME_RE.match(self.user.replace("\\", "")):
            raise ValueError(f"utilisateur invalide : {self.user!r}")
        if self.key:
            # "~/.ssh/claude_dev" doit marcher sur le mini PC comme sous Windows.
            self.key = os.path.expanduser(self.key)
        if not self.allowed_paths:
            raise ValueError("allowed_paths ne peut pas être vide")
        self.allowed_paths = [self.normpath(p) for p in self.allowed_paths]
        for p in self.allowed_paths:
            if not self.isabs(p):
                raise ValueError(f"allowed_path doit être absolu : {p!r}")
            if self.is_root(p):
                raise ValueError(f"allowed_path ne peut pas être une racine : {p!r}")
        for pname, proj in self.projects.items():
            if not _NAME_RE.match(pname):
                raise ValueError(f"nom de projet invalide : {pname!r}")
            proj.path = self.normpath(proj.path)
        for sname, spath in list(self.log_sources.items()):
            if not _NAME_RE.match(sname):
                raise ValueError(f"nom de source de logs invalide : {sname!r}")
            self.log_sources[sname] = self.normpath(spath)
        return self

    # --- helpers de chemins selon l'OS cible -------------------------------------
    @property
    def is_windows(self) -> bool:
        return self.os == "windows"

    @property
    def is_posix_shell(self) -> bool:
        return self.shell == "posix"

    def normpath(self, p: str) -> str:
        if self.is_windows:
            return ntpath.normpath(p.replace("/", "\\"))
        return posixpath.normpath(p)

    def isabs(self, p: str) -> bool:
        if self.is_windows:
            drive, rest = ntpath.splitdrive(p)
            return bool(re.match(r"^[A-Za-z]:$", drive)) and rest.startswith("\\")
        return p.startswith("/")

    def is_root(self, p: str) -> bool:
        if self.is_windows:
            return bool(re.match(r"^[A-Za-z]:\\?$", p))
        return p == "/"

    def has_level(self, level: str) -> bool:
        return level in self.permissions


class Limits(_Strict):
    max_read_bytes: int = 1_000_000
    max_write_bytes: int = 2_000_000
    max_output_chars: int = 60_000
    max_list_entries: int = 2_000
    max_search_results: int = 200


class Timeouts(_Strict):
    default: int = 60
    tests: int = 900
    build: int = 1800
    git_pull: int = 180
    docker_compose: int = 900


class Policies(_Strict):
    mode: Literal["safe", "dev", "admin"] = "dev"
    secret_patterns: list[str] = Field(default_factory=list)
    denied_paths_posix: list[str] = Field(default_factory=list)
    denied_paths_windows: list[str] = Field(default_factory=list)
    blocked_command_patterns: list[str] = Field(default_factory=list)
    protect_git_dir: bool = True
    limits: Limits = Field(default_factory=Limits)
    timeouts: Timeouts = Field(default_factory=Timeouts)
    audit_log: str = "logs/audit.log"

    @field_validator("secret_patterns")
    @classmethod
    def _globs(cls, v: list[str]) -> list[str]:
        for g in v:
            if not _GLOB_RE.match(g):
                raise ValueError(f"motif de secret invalide (caractères autorisés : alnum . _ - * ?) : {g!r}")
        return v


class Config(BaseModel):
    hosts: dict[str, HostConfig]
    policies: Policies
    base_dir: Path

    @property
    def mode_levels(self) -> set[str]:
        return MODE_LEVELS[self.policies.mode]

    def allowed(self, host: HostConfig, level: str) -> bool:
        return level in self.mode_levels and host.has_level(level)


def _read_yaml(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path} : un mapping YAML est attendu")
    return data


def resolve_config_dir(config_dir: str | os.PathLike | None = None) -> Path:
    base = Path(__file__).resolve().parent.parent
    return Path(config_dir or os.environ.get("REMOTEDEV_CONFIG_DIR") or base / "config")


# --- édition de hosts.yaml (utilisée par l'interface) ---------------------------------

_HOSTS_HEADER = (
    "# Géré par l'interface RemoteDev (bouton Ajouter / Modifier). Les commentaires ne sont pas conservés.\n"
    "# Référence des champs : hosts.example.yaml\n\n"
)


def read_hosts_raw(config_dir: str | os.PathLike | None = None) -> dict[str, dict]:
    """Contenu brut de hosts.yaml (vide si le fichier n'existe pas)."""
    raw = _read_yaml(resolve_config_dir(config_dir) / "hosts.yaml").get("hosts") or {}
    return {str(k): dict(v or {}) for k, v in raw.items()}


def _write_hosts_raw(hosts: dict[str, dict], config_dir: str | os.PathLike | None) -> None:
    path = resolve_config_dir(config_dir) / "hosts.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.with_name("hosts.yaml.bak").write_bytes(path.read_bytes())
    body = yaml.safe_dump({"hosts": hosts}, sort_keys=False, allow_unicode=True, default_flow_style=False)
    tmp = path.with_name("hosts.yaml.tmp")
    tmp.write_text(_HOSTS_HEADER + body, encoding="utf-8")
    os.replace(tmp, path)


def save_host(name: str, data: dict, old_name: str | None = None,
              config_dir: str | os.PathLike | None = None) -> HostConfig:
    """Valide puis enregistre une machine. `old_name` : renommage d'une entrée existante."""
    if not _NAME_RE.match(name):
        raise ValueError(f"nom de machine invalide : {name!r} (lettres, chiffres, . _ @ -)")
    hc = HostConfig.model_validate({**data, "name": name})
    hosts = read_hosts_raw(config_dir)
    if name in hosts and name != old_name:
        raise ValueError(f"une machine nommée {name!r} existe déjà")
    if old_name and old_name != name:
        hosts = {(name if k == old_name else k): v for k, v in hosts.items()}
    hosts[name] = data
    _write_hosts_raw(hosts, config_dir)
    from . import credentials

    if old_name and old_name != name:
        credentials.rename(old_name, name, config_dir)
    if hc.auth != "password":
        credentials.delete_password(name, config_dir)
    return hc


def delete_host(name: str, config_dir: str | os.PathLike | None = None) -> None:
    from . import credentials

    hosts = read_hosts_raw(config_dir)
    if hosts.pop(name, None) is not None:
        _write_hosts_raw(hosts, config_dir)
    credentials.delete_password(name, config_dir)


def load_config(config_dir: str | os.PathLike | None = None) -> Config:
    base = Path(__file__).resolve().parent.parent
    cdir = resolve_config_dir(config_dir)
    hosts_file = cdir / "hosts.yaml"
    if not hosts_file.exists():
        raise FileNotFoundError(
            f"{hosts_file} introuvable. Copier config/hosts.example.yaml vers config/hosts.yaml."
        )
    raw_hosts = _read_yaml(hosts_file).get("hosts") or {}
    hosts: dict[str, HostConfig] = {}
    for name, data in raw_hosts.items():
        if not _NAME_RE.match(str(name)):
            raise ValueError(f"nom d'hôte MCP invalide : {name!r}")
        hc = HostConfig.model_validate({**(data or {}), "name": str(name)})
        hc._config_dir = cdir
        hosts[str(name)] = hc
    policies = Policies.model_validate(_read_yaml(cdir / "policies.yaml"))
    env_mode = os.environ.get("REMOTEDEV_MODE")
    if env_mode:
        policies.mode = env_mode  # type: ignore[assignment]
        Policies.model_validate(policies.model_dump())
    audit = Path(policies.audit_log)
    if not audit.is_absolute():
        policies.audit_log = str(base / audit)
    return Config(hosts=hosts, policies=policies, base_dir=base)
