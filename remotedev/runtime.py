"""Contexte d'exécution partagé par les outils : config, backends, scripts, audit."""

from __future__ import annotations

import functools
import inspect
import json
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable

from .backends import ExecResult, get_backend
from .backends.base import RC_DENIED, RC_SECRET
from .config import Config, HostConfig
from .security.errors import SecretDenied, SecurityDenied, ToolError
from .security.path_filter import check_path, posix_guard, powershell_guard
from .security.validator import audit_params, redact


def sh_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


def ps_quote(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


PS_PRELUDE = r"""
$global:RD_RC = 0
$ProgressPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch {}
$OutputEncoding = New-Object System.Text.UTF8Encoding $false
function Rd-Err([string]$m) {
  if ($global:RD_WINRM) { [void]$global:RD_ERRBUF.AppendLine($m) } else { [Console]::Error.WriteLine($m) }
}
function Rd-Fail([int]$Code, [string]$Msg) { throw (New-Object System.Exception ('RDFAIL:' + $Code + ':' + $Msg)) }
function Rd-Exec([string]$Exe, [string[]]$Argv) {
  if (-not (Get-Command $Exe -ErrorAction SilentlyContinue)) { Rd-Err ("commande introuvable : " + $Exe); $global:RD_RC = 127; return }
  $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  try { & $Exe @Argv 2>&1 | ForEach-Object { "$_" } } finally { $ErrorActionPreference = $old }
  $global:RD_RC = $LASTEXITCODE
}
function Rd-Shell([string]$Code) {
  $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  $global:LASTEXITCODE = 0
  try { & ([scriptblock]::Create($Code)) 2>&1 | ForEach-Object { "$_" } } finally { $ErrorActionPreference = $old }
  $global:RD_RC = $LASTEXITCODE
}
"""

PS_EPILOGUE = r"""
} catch {
  $m = $_.Exception.Message
  if ($m -match '^RDFAIL:(\d+):(.*)$') {
    $global:RD_RC = [int]$Matches[1]
    if ($global:RD_RC -eq 98) { Rd-Err 'RD_SECRET' }
    elseif ($global:RD_RC -eq 97) { Rd-Err ('RD_DENIED: ' + $Matches[2]) }
    else { Rd-Err $Matches[2] }
  } else { $global:RD_RC = 1; Rd-Err ('ERREUR: ' + $m) }
}
if (-not $global:RD_WINRM) { exit $global:RD_RC }
"""


@dataclass
class ToolSpec:
    func: Callable[..., Awaitable[str]]
    level: str
    read_only: bool
    destructive: bool
    description: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


REGISTRY: list[ToolSpec] = []


class Runtime:
    def __init__(self, config: Config):
        self.config = config
        self.policies = config.policies
        self._audit_lock = threading.Lock()

    # ------------------------------------------------------------------ hôtes
    def host(self, name: str) -> HostConfig:
        h = self.config.hosts.get(name)
        if h is None:
            raise ToolError(f"hôte inconnu : {name!r}. Hôtes : {', '.join(sorted(self.config.hosts))}")
        return h

    def require(self, host: HostConfig, level: str) -> None:
        if level not in self.config.mode_levels:
            raise SecurityDenied(f"niveau {level.upper()} désactivé (mode global {self.policies.mode.upper()})")
        if not host.has_level(level):
            raise SecurityDenied(f"niveau {level.upper()} non accordé sur l'hôte {host.name}")

    def path(self, host: HostConfig, path: str, mode: str = "read") -> str:
        return check_path(host, self.policies, path, mode)

    def project_path(self, host: HostConfig, project: str) -> str:
        """`project` : nom déclaré dans `projects`, nom de dossier d'un allowed_path, ou chemin absolu."""
        if project in host.projects:
            return self.path(host, host.projects[project].path, "list")
        for root in host.allowed_paths:
            leaf = root.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
            if project == leaf:
                return root
        return self.path(host, project, "list")

    def project_config(self, host: HostConfig, path: str):
        for proj in host.projects.values():
            same = proj.path.lower() == path.lower() if host.is_windows else proj.path == path
            if same:
                return proj
        return None

    # ---------------------------------------------------------------- scripts
    def script(self, host: HostConfig, body: str) -> str:
        if host.is_posix_shell:
            # PYTHONDONTWRITEBYTECODE : un patch de même taille dans la même seconde laisserait
            # un .pyc périmé considéré valide -> tests relancés sur l'ancien code.
            env = "export CI=1 NO_COLOR=1 GIT_TERMINAL_PROMPT=0 PYTHONDONTWRITEBYTECODE=1 LC_ALL=C.UTF-8\n"
            if host.path_prepend:
                env += "PATH=" + sh_quote(":".join(host.path_prepend)) + ':"$PATH"; export PATH\n'
            return "set -u\n" + env + posix_guard(host, self.policies) + body
        env = "$env:CI = '1'; $env:NO_COLOR = '1'; $env:GIT_TERMINAL_PROMPT = '0'; $env:PYTHONDONTWRITEBYTECODE = '1'\n"
        if host.path_prepend:
            env += "$env:PATH = " + ps_quote(";".join(host.path_prepend) + ";") + " + $env:PATH\n"
        return PS_PRELUDE + env + powershell_guard(host, self.policies) + "try {\n" + body + PS_EPILOGUE

    async def run(
        self, host: HostConfig, body: str, *, stdin: bytes | None = None, timeout: int | None = None
    ) -> ExecResult:
        backend = get_backend(host)
        res = await backend.run(self.script(host, body), stdin=stdin, timeout=timeout or self.policies.timeouts.default)
        if res.exit_code == RC_SECRET:
            raise SecretDenied()
        if res.exit_code == RC_DENIED:
            msg = next((ln for ln in res.stderr.splitlines() if "RD_DENIED" in ln), "RD_DENIED")
            raise SecurityDenied(msg.split("RD_DENIED:", 1)[-1].strip() or "refusé par la garde distante")
        if host.backend == "ssh" and res.exit_code == 255 and not res.stdout:
            raise ToolError(f"connexion SSH impossible vers {host.name} : {res.stderr.strip()[:500]}")
        return res

    # ---------------------------------------------------------------- sortie
    def clip(self, text: str, limit: int | None = None) -> str:
        limit = limit or self.policies.limits.max_output_chars
        text = redact(text)
        if len(text) <= limit:
            return text
        head = limit // 3
        tail = limit - head
        return f"{text[:head]}\n\n[... {len(text) - limit} caractères tronqués ...]\n\n{text[-tail:]}"

    def format(self, res: ExecResult, title: str = "") -> str:
        status = "TIMEOUT" if res.timed_out else ("OK" if res.exit_code == 0 else "ÉCHEC")
        parts = [f"{title} — {status} (exit_code={res.exit_code}, {res.duration:.1f}s)".strip(" —")]
        out = res.stdout.strip("\n")
        err = res.stderr.strip("\n")
        if out:
            parts.append(self.clip(out))
        if err:
            parts.append("--- stderr ---\n" + self.clip(err, self.policies.limits.max_output_chars // 4))
        return "\n".join(parts)

    # ---------------------------------------------------------------- audit
    def audit(self, entry: dict[str, Any]) -> None:
        path = Path(self.policies.audit_log)
        path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(entry, ensure_ascii=False, default=str)
        with self._audit_lock, path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")


_RUNTIME: Runtime | None = None


def set_runtime(rt: Runtime) -> None:
    global _RUNTIME
    _RUNTIME = rt


def rt() -> Runtime:
    if _RUNTIME is None:
        raise RuntimeError("runtime non initialisé")
    return _RUNTIME


def tool(level: str, *, read_only: bool = True, destructive: bool = False):
    """Déclare un outil MCP : niveau de permission, annotations, audit automatique."""

    def decorator(func: Callable[..., Awaitable[str]]):
        sig = inspect.signature(func)

        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> str:
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            params = dict(bound.arguments)
            start = time.monotonic()
            entry: dict[str, Any] = {
                "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "tool": func.__name__,
                "level": level,
                "host": params.get("host"),
                "params": audit_params({k: v for k, v in params.items() if k != "host"}),
            }
            try:
                result = await func(*args, **kwargs)
                entry["result"] = "SUCCESS"
                return result
            except SecurityDenied as exc:
                entry["result"] = "DENIED"
                entry["reason"] = str(exc)
                raise
            except ToolError as exc:
                entry["result"] = "ERROR"
                entry["reason"] = str(exc)[:500]
                raise
            except Exception as exc:
                entry["result"] = "ERROR"
                entry["reason"] = f"{type(exc).__name__}: {str(exc)[:500]}"
                raise ToolError(f"{type(exc).__name__}: {exc}") from exc
            finally:
                entry["duration"] = round(time.monotonic() - start, 3)
                try:
                    rt().audit(entry)
                except Exception:
                    pass

        REGISTRY.append(ToolSpec(wrapper, level, read_only, destructive, (func.__doc__ or "").strip()))
        return wrapper

    return decorator
