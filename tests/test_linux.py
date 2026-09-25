"""Mini PC Linux : tableau de bord texte, lanceur sh, stdio via le lanceur."""

from __future__ import annotations

import json
import os
import sys
import time

import pytest

from conftest import ROOT, write_config
from remotedev import tui
from remotedev.config import HostConfig

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="lanceur sh / pty : Linux/macOS")


def test_render_stopped_and_running():
    st = tui.TuiState()
    lines = [t for t, _ in tui.render(0, [], [], ["h1"], st)]
    assert any("HTTP  : ○ arrêté" in t for t in lines)
    assert any(t.strip().startswith("h1") for t in lines)

    inst = {"pid": 1, "transport": "http", "mode": "safe", "status": "en cours", "tunnel": True,
            "url": "https://a.trycloudflare.com/SECRET/mcp", "started_at": time.time(), "expires_at": time.time() + 600}
    out = tui.render(time.time(), [inst], [{"ts": "2026-09-25T10:00:00", "tool": "read_file", "host": "h1",
                                            "result": "DENIED"}], ["h1"], st)
    text = "\n".join(t for t, _ in out)
    assert "● en cours" in text and "SECRET" not in text and "••••••" in text
    refus = [(t, style) for t, style in out if "REFUS" in t]
    assert len(refus) == 1 and "read_file" in refus[0][0] and refus[0][1] == "bad"
    st.show_secret = True
    assert "SECRET" in "\n".join(t for t, _ in tui.render(time.time(), [inst], [], [], st))


def test_keys(monkeypatch):
    launched = []
    monkeypatch.setattr(tui, "launch_http", lambda m, dev, tun: launched.append((m, dev, tun)) or None)
    monkeypatch.setattr(tui, "stop_http", lambda: 1)
    st = tui.TuiState()
    for k in "+++--":
        tui.handle_key(k, st, False)
    assert st.minutes == 35
    tui.handle_key("s", st, False)
    assert launched == [(35, False, True)]
    st.launching_since = None
    tui.handle_key("d", st, False)
    tui.handle_key("s", st, False)            # DEV : confirmation demandée, rien lancé
    assert st.confirm_dev and len(launched) == 1
    tui.handle_key("n", st, False)            # refus
    assert len(launched) == 1 and "annulé" in st.message
    tui.handle_key("s", st, False)
    tui.handle_key("o", st, False)            # confirmation
    assert launched[-1] == (35, True, True)
    tui.handle_key("x", st, True)
    assert "Arrêt demandé" in st.message
    assert tui.handle_key("q", st, False) is False


def test_key_path_tilde_expanded():
    h = HostConfig(os="linux", backend="ssh", host="h", key="~/.ssh/claude_dev", allowed_paths=["/srv/p"])
    assert not h.key.startswith("~") and h.key.endswith("/.ssh/claude_dev")


@posix_only
def test_tui_in_real_terminal(tmp_path, monkeypatch):
    import pty
    import select

    proj = tmp_path / "p" / "demo"
    proj.mkdir(parents=True)
    env = {**os.environ, "TERM": "xterm-256color", "REMOTEDEV_RUN_DIR": str(tmp_path / "run"),
           "REMOTEDEV_CONFIG_DIR": str(write_config(tmp_path / "cfg", proj, tmp_path / "audit.log"))}
    env.pop("DISPLAY", None)
    env.pop("WAYLAND_DISPLAY", None)
    pid, fd = pty.fork()
    if pid == 0:  # enfant : --ui sans écran doit basculer en mode texte
        os.execve(sys.executable, [sys.executable, str(ROOT / "server.py"), "--ui"], env)
    out = b""
    deadline = time.time() + 20
    while time.time() < deadline and b"Machines" not in out:
        if select.select([fd], [], [], 0.5)[0]:
            try:
                out += os.read(fd, 65536)
            except OSError:
                break
    os.write(fd, b"q")
    _, status = os.waitpid(pid, 0)
    assert b"RemoteDev" in out and b"local-sh" in out and b"arr" in out
    assert os.waitstatus_to_exitcode(status) == 0


@posix_only
async def test_stdio_through_sh_launcher(tmp_path):
    """Claude Desktop sur le PC -> `ssh minipc remotedev.sh stdio` : stdout doit rester propre."""
    from mcp.client.session import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    proj = tmp_path / "p" / "demo"
    proj.mkdir(parents=True)
    cdir = write_config(tmp_path / "cfg", proj, tmp_path / "audit.log")
    params = StdioServerParameters(command="sh", args=[str(ROOT / "remotedev.sh"), "stdio"],
                                   env={**os.environ, "REMOTEDEV_CONFIG_DIR": str(cdir),
                                        "REMOTEDEV_RUN_DIR": str(tmp_path / "run")})
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            names = {t.name for t in (await session.list_tools()).tools}
            assert "git_status" in names
            # pendant la session, l'instance stdio est visible dans le tableau de bord
            files = [json.loads(f.read_text()) for f in (tmp_path / "run").glob("*.json")]
            assert [f["transport"] for f in files] == ["stdio"]
