from __future__ import annotations

import json

import pytest

from conftest import SHELLS
from remotedev.security.errors import SecretDenied, SecurityDenied, ToolError
from remotedev.tools import docker, files, git, services, system, tests as testing

pytestmark = pytest.mark.asyncio

HOST = {"posix": "local-sh", "powershell": "local-ps", "winrm-mock": "local-winrm", "ssh-posix": "ssh-sh", "ssh-powershell": "ssh-ps"}


@pytest.fixture(params=SHELLS)
def host(request):
    return HOST[request.param]


async def test_read_file(workspace, host):
    out = await files.read_file(host, str(workspace["proj"] / "notes.txt"))
    assert "hello world" in out and "second line" in out


async def test_read_secret_denied(workspace, host):
    with pytest.raises(SecretDenied):
        await files.read_file(host, str(workspace["proj"] / ".env"))


async def test_symlink_to_secret_denied_remotely(workspace, host):
    # Le nom "innocent.txt" passe le contrôle lexical ; la garde distante doit bloquer.
    with pytest.raises(SecurityDenied):
        await files.read_file(host, str(workspace["proj"] / "innocent.txt"))


async def test_symlink_escape_denied(workspace, host):
    with pytest.raises(SecurityDenied):
        await files.read_file(host, str(workspace["proj"] / "escape"))
    with pytest.raises(SecurityDenied):
        await files.read_file(host, str(workspace["proj"] / "escape_dir" / "private.txt"))
    with pytest.raises(SecurityDenied):
        await files.write_file(host, str(workspace["proj"] / "escape_dir" / "new.txt"), "x")
    assert not (workspace["outside"] / "new.txt").exists()


async def test_traversal_denied(workspace, host):
    with pytest.raises(SecurityDenied):
        await files.read_file(host, str(workspace["proj"]) + "/../outside/private.txt")
    with pytest.raises(SecurityDenied):
        await files.read_file(host, "/etc/passwd")


async def test_write_and_patch_roundtrip(workspace, host):
    target = workspace["proj"] / "src" / "new_module.py"
    await files.write_file(host, str(target), "x = 1\ny = 'é'\n")
    assert target.read_text(encoding="utf-8") == "x = 1\ny = 'é'\n"
    await files.patch_file(host, str(target), "x = 1", "x = 42")
    assert target.read_text(encoding="utf-8") == "x = 42\ny = 'é'\n"
    with pytest.raises(ToolError):
        await files.patch_file(host, str(target), "absent", "z")


async def test_patch_ambiguous_and_crlf(workspace, host):
    target = workspace["proj"] / "crlf.txt"
    target.write_bytes(b"a = 1\r\nb = 1\r\na = 1\r\n")
    with pytest.raises(ToolError, match="2 fois"):
        await files.patch_file(host, str(target), "a = 1", "a = 2")
    await files.patch_file(host, str(target), "b = 1\na = 1", "b = 2\na = 3")
    assert target.read_bytes() == b"a = 1\r\nb = 2\r\na = 3\r\n"


async def test_write_requires_parent_unless_create_dirs(workspace, host):
    target = workspace["proj"] / "deep" / "dir" / "f.txt"
    with pytest.raises(ToolError):
        await files.write_file(host, str(target), "x")
    await files.write_file(host, str(target), "x", create_dirs=True)
    assert target.read_text() == "x"


async def test_write_secret_and_git_denied(workspace, host):
    with pytest.raises(SecretDenied):
        await files.write_file(host, str(workspace["proj"] / ".env"), "X=1")
    with pytest.raises(SecurityDenied):
        await files.write_file(host, str(workspace["proj"] / ".git" / "hooks" / "pre-commit"), "evil")


async def test_list_files(workspace, host):
    out = await files.list_files(host, str(workspace["proj"]), recursive=True)
    assert "src/app.py" in out.replace("\\", "/")
    assert ".git/ [non parcouru]" in out.replace("\\", "/")
    assert "HEAD" not in out


async def test_search_excludes_secrets(workspace, host):
    out = await files.search_files(host, "demo", "super-secret")
    assert "super-secret" not in out
    out = await files.search_files(host, "demo", "return a - b")
    assert "app.py" in out
    out = await files.search_files(host, "demo", "*.py", mode="name")
    assert "test_app.py" in out


async def test_git_tools(workspace, host):
    (workspace["proj"] / "notes.txt").write_text("changed\n")
    (workspace["proj"] / ".env").write_text("API_TOKEN=leaked-new-value\n")
    status = await git.git_status(host, "demo")
    assert "notes.txt" in status
    diff = await git.git_diff(host, "demo")
    assert "+changed" in diff
    assert "leaked-new-value" not in diff
    log = await git.git_log(host, "demo", limit=5)
    assert "init" in log


async def test_run_tests_detects_pytest(workspace, host):
    out = await testing.run_tests(host, "demo")
    assert "pytest" in out and "ÉCHEC" in out and "assert" in out
    await files.patch_file(host, str(workspace["proj"] / "src" / "app.py"), "return a - b", "return a + b")
    out = await testing.run_tests(host, "demo", target="tests/test_app.py::test_add")
    assert "OK" in out and "1 passed" in out


async def test_readonly_host_cannot_write(workspace):
    with pytest.raises(SecurityDenied, match="DEV"):
        await files.write_file("readonly", str(workspace["proj"] / "x.txt"), "x")


async def test_unknown_host(workspace):
    with pytest.raises(ToolError, match="hôte inconnu"):
        await files.read_file("nope", "/tmp/x")


async def test_docker_disabled(workspace):
    with pytest.raises(SecurityDenied, match="docker désactivé"):
        await docker.docker_ps("local-sh")


async def test_restart_service_whitelist(workspace):
    with pytest.raises(SecurityDenied, match="liste blanche"):
        await services.restart_dev_service("local-sh", "sshd")


async def test_host_list(workspace):
    out = await system.host_list()
    assert "local-sh" in out and "mode global : DEV" in out


async def test_audit_log_never_contains_content(workspace, host):
    await files.write_file(host, str(workspace["proj"] / "a.txt"), "TOP-SECRET-CONTENT")
    with pytest.raises(SecretDenied):
        await files.read_file(host, str(workspace["proj"] / ".env"))
    raw = workspace["audit"].read_text(encoding="utf-8")
    assert "TOP-SECRET-CONTENT" not in raw
    entries = [json.loads(line) for line in raw.splitlines()]
    assert any(e["tool"] == "write_file" and e["result"] == "SUCCESS" for e in entries)
    assert any(e["tool"] == "read_file" and e["result"] == "DENIED" for e in entries)


async def test_large_write_roundtrip(workspace, host):
    target = workspace["proj"] / "big.txt"
    content = ("ligne é ✓ " * 20 + "\n") * 6000  # ~1,5 Mo : stdin, base64, pas de limite de ligne de commande
    await files.write_file(host, str(target), content)
    assert target.read_text(encoding="utf-8") == content


async def test_timeout(workspace, host):
    from remotedev.runtime import rt

    r = rt()
    h = r.host(host)
    body = "sleep 5\n" if h.is_posix_shell else "Start-Sleep -Seconds 5\n"
    res = await r.run(h, body, timeout=1)
    assert res.timed_out and res.exit_code == 124
