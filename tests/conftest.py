from __future__ import annotations

import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from remotedev.app import build_server  # noqa: E402
from remotedev.config import load_config  # noqa: E402

HAS_PWSH = shutil.which("pwsh") is not None
SHELLS = ["posix"] + (["powershell", "winrm-mock"] if HAS_PWSH else [])

# WinRM ne peut pas être testé sans Windows : on remplace Invoke-Command par une fonction
# (prioritaire sur la cmdlet) qui exécute le scriptblock localement. Toute la logique du
# backend (transport base64, ArgumentList, objet retour, codes de sortie) est exercée ;
# seule la couche réseau WinRM ne l'est pas.
WINRM_MOCK = r"""
function Invoke-Command {
  param([string]$ComputerName, $ErrorAction, [object[]]$ArgumentList, [scriptblock]$ScriptBlock,
        $Port, $UseSSL, $Authentication, $ConfigurationName)
  & $ScriptBlock @ArgumentList
}
"""

# Intégration SSH réelle (optionnelle) :
#   REMOTEDEV_SSH_TEST="user@host:port:/chemin/cle:/dossier/distant/inscriptible"
# Le dossier doit être sur CETTE machine (les tests préparent les fichiers localement) :
# sert à valider le transport ssh -> sh et ssh -> pwsh contre un sshd local.
SSH_TEST = os.environ.get("REMOTEDEV_SSH_TEST")
if SSH_TEST:
    _userhost, _port, SSH_KEY, SSH_WORKDIR = SSH_TEST.split(":", 3)
    SSH_USER, SSH_HOST = _userhost.split("@", 1)
    SHELLS += ["ssh-posix", "ssh-powershell"]


def write_config(cdir: Path, proj: Path, audit: Path, mode: str = "dev", extra_host: dict | None = None) -> Path:
    cdir.mkdir(parents=True, exist_ok=True)
    base = {
        "os": "linux",
        "backend": "local",
        "permissions": ["read", "dev"],
        "allowed_paths": [str(proj)],
        "projects": {"demo": {"path": str(proj)}},
        "docker": {"enabled": False},
        "services": {"restartable": ["demo-svc"]},
    }
    hosts = {
        "local-sh": {**base, "shell": "posix"},
        "local-ps": {**base, "shell": "powershell"},
        "readonly": {**base, "shell": "posix", "permissions": ["read"]},
        "local-winrm": {**base, "backend": "winrm", "host": "localhost", "shell": "powershell"},
    }
    if SSH_TEST:
        ssh = {**base, "backend": "ssh", "host": SSH_HOST, "user": SSH_USER, "port": int(_port), "key": SSH_KEY}
        hosts["ssh-sh"] = {**ssh, "shell": "posix"}
        hosts["ssh-ps"] = {**ssh, "shell": "powershell"}
    if extra_host:
        hosts.update(extra_host)
    (cdir / "hosts.yaml").write_text(yaml.safe_dump({"hosts": hosts}), encoding="utf-8")
    pol = yaml.safe_load((ROOT / "config" / "policies.yaml").read_text(encoding="utf-8"))
    pol["mode"] = mode
    pol["audit_log"] = str(audit)
    (cdir / "policies.yaml").write_text(yaml.safe_dump(pol), encoding="utf-8")
    return cdir


@pytest.fixture(autouse=True)
def _mock_winrm(monkeypatch):
    from remotedev.backends.powershell_backend import WinRMBackend

    original = WinRMBackend.wrapper
    monkeypatch.setattr(WinRMBackend, "wrapper", lambda self, script: WINRM_MOCK + original(self, script))


@pytest.fixture
def workspace(tmp_path: Path, request):
    callspec = getattr(request.node, "callspec", None)
    over_ssh = bool(callspec and str(callspec.params.get("host", "")).startswith("ssh"))
    base = Path(SSH_WORKDIR) / f"rd-{uuid.uuid4().hex[:8]}" if over_ssh else tmp_path
    proj = base / "projects" / "demo"
    (proj / "src").mkdir(parents=True)
    (proj / "src" / "app.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
    (proj / "tests").mkdir()
    (proj / "tests" / "test_app.py").write_text(
        "import sys, pathlib\nsys.path.insert(0, str(pathlib.Path(__file__).parent.parent / 'src'))\n"
        "from app import add\n\ndef test_add():\n    assert add(2, 3) == 5\n",
        encoding="utf-8",
    )
    (proj / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    (proj / ".env").write_text("API_TOKEN=super-secret-value\n", encoding="utf-8")
    (proj / "notes.txt").write_text("hello world\nsecond line\n", encoding="utf-8")
    # Faux venv pointant vers le Python qui exécute les tests (pytest y est installé).
    (proj / ".venv" / "bin").mkdir(parents=True)
    shim = proj / ".venv" / "bin" / "python"
    shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
    shim.chmod(0o755)
    (proj / ".gitignore").write_text(".venv/\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", "-b", "main", str(proj)], check=True)
    subprocess.run(["git", "-C", str(proj), "add", "."], check=True)
    subprocess.run(["git", "-C", str(proj), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"],
                   check=True)
    # Cible hors projet + lien symbolique qui tente de s'échapper.
    outside = base / "outside"
    outside.mkdir()
    (outside / "private.txt").write_text("PRIVATE DATA\n", encoding="utf-8")
    (proj / "escape").symlink_to(outside / "private.txt")
    (proj / "escape_dir").symlink_to(outside)
    (proj / "innocent.txt").symlink_to(proj / ".env")

    if over_ssh:
        subprocess.run(["chown", "-R", SSH_USER, str(base)], check=True)
    audit = tmp_path / "audit.log"
    cdir = write_config(tmp_path / "config", proj, audit)
    config = load_config(cdir)
    build_server(config)
    yield {"proj": proj, "outside": outside, "audit": audit, "config": config, "tmp": tmp_path}
    if over_ssh:
        shutil.rmtree(base, ignore_errors=True)
