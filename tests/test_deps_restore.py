"""install_dependencies et restore_file."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from conftest import SHELLS
from remotedev.security.errors import SecretDenied, SecurityDenied, ToolError
from remotedev.tools import deps, git

HOST = {"posix": "local-sh", "powershell": "local-ps", "winrm-mock": "local-winrm",
        "ssh-posix": "ssh-sh", "ssh-powershell": "ssh-ps"}


@pytest.fixture(params=SHELLS)
def host(request):
    return HOST[request.param]


# --- plan (pur) -----------------------------------------------------------------------

def test_plan_node_variants():
    assert deps.plan_install({"package.json", "package-lock.json"}, False) == [("node", ["npm", "ci"])]
    assert deps.plan_install({"package.json"}, True) == [("node", ["npm.cmd", "install"])]
    assert deps.plan_install({"package.json", "pnpm-lock.yaml"}, False, ignore_scripts=True) == \
        [("node", ["pnpm", "install", "--frozen-lockfile", "--ignore-scripts"])]


def test_plan_python_creates_venv_only_when_missing():
    steps = deps.plan_install({"requirements.txt"}, False)
    assert steps[0] == ("python", ["python3", "-m", "venv", ".venv"])
    assert steps[1][1][:3] == ["./.venv/bin/python", "-m", "pip"] and steps[1][1][-2:] == ["-r", "requirements.txt"]
    steps = deps.plan_install({"requirements.txt", ".venv/Scripts/python.exe"}, True)
    assert len(steps) == 1 and steps[0][1][0] == ".\\.venv\\Scripts\\python.exe"
    # pyproject.toml de simple configuration (pas de [build-system]) : rien à installer
    assert deps.plan_install({"pyproject.toml"}, False) == []
    assert deps.plan_install({"pyproject.toml", "pyproject:build"}, False)[-1][1][-2:] == ["-e", "."]


def test_plan_kind_filter():
    m = {"package.json", "requirements.txt", "go.mod", "dotnet"}
    assert [k for k, _ in deps.plan_install(m, False, kind="go")] == ["go"]
    assert [k for k, _ in deps.plan_install(m, False)] == ["node", "python", "python", "go", "dotnet"]


# --- exécution réelle -----------------------------------------------------------------

@pytest.mark.asyncio
async def test_install_python_into_new_venv(workspace, host):
    proj = workspace["proj"]
    shutil.rmtree(proj / ".venv")
    (proj / "requirements.txt").write_text("# aucune dépendance : pas de réseau requis\n")
    out = await deps.install_dependencies(host, "demo", kind="python")
    assert "OK" in out, out
    assert (proj / ".venv" / "bin" / "python").exists()


@pytest.mark.asyncio
async def test_install_stops_on_first_failure(workspace, host):
    (workspace["proj"] / "requirements.txt").write_text("ce-paquet-n-existe-pas-rd==0.0.0\n")
    (workspace["proj"] / "go.mod").write_text("module x\n")
    out = await deps.install_dependencies(host, "demo")
    assert "ÉCHEC" in out and "ACCESS DENIED" not in out


@pytest.mark.skipif(shutil.which("npm") is None, reason="npm absent")
@pytest.mark.asyncio
async def test_install_node(workspace, host):
    (workspace["proj"] / "package.json").write_text('{"name": "demo", "version": "1.0.0"}\n')
    out = await deps.install_dependencies(host, "demo", kind="node")
    assert "OK" in out, out


@pytest.mark.asyncio
async def test_install_nothing_detected(workspace, host):
    (workspace["proj"] / "pytest.ini").unlink()
    with pytest.raises(ToolError, match="aucune dépendance"):
        await deps.install_dependencies(host, "demo")


@pytest.mark.asyncio
async def test_readonly_cannot_install(workspace):
    with pytest.raises(SecurityDenied, match="DEV"):
        await deps.install_dependencies("readonly", "demo")


@pytest.mark.asyncio
async def test_restore_file(workspace, host):
    proj = workspace["proj"]
    (proj / "notes.txt").write_text("cassé par Claude\n")
    out = await git.restore_file(host, "demo", str(proj / "notes.txt"))
    assert "OK" in out, out
    assert (proj / "notes.txt").read_text() == "hello world\nsecond line\n"


@pytest.mark.asyncio
async def test_restore_refuses_dirs_globs_secrets(workspace, host):
    proj = workspace["proj"]
    (proj / "src" / "app.py").write_text("modifié\n")
    out = await git.restore_file(host, "demo", str(proj / "src"))
    assert "ÉCHEC" in out and "pas un fichier" in out
    assert (proj / "src" / "app.py").read_text() == "modifié\n"   # rien restauré
    out = await git.restore_file(host, "demo", str(proj / "src" / "*.py"))
    assert (proj / "src" / "app.py").read_text() == "modifié\n"   # le joker n'a rien touché
    assert "OK" not in out.splitlines()[0]
    with pytest.raises(SecretDenied):
        await git.restore_file(host, "demo", str(proj / ".env"))
    with pytest.raises(SecurityDenied):
        await git.restore_file(host, "demo", str(proj / ".git" / "config"))


@pytest.mark.asyncio
async def test_restore_untracked_file_reports_error(workspace, host):
    (workspace["proj"] / "nouveau.txt").write_text("x\n")
    out = await git.restore_file(host, "demo", str(workspace["proj"] / "nouveau.txt"))
    assert "ÉCHEC" in out
    assert (workspace["proj"] / "nouveau.txt").exists()
