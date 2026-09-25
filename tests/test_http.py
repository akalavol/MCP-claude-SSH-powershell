"""Mode HTTP à la demande : secret dans le chemin, JSON sans SSE, SAFE forcé."""

from __future__ import annotations

import asyncio
import os
import socket
import stat
import sys

import urllib.error
import urllib.request
import pytest
import uvicorn

from conftest import write_config
from remotedev.config import load_config
from remotedev.http_remote import _start_tunnel, build_http_app

pytestmark = pytest.mark.asyncio

try:  # mcp >= 2
    from mcp.client.streamable_http import streamable_http_client as _client
except ImportError:  # mcp 1.x
    from mcp.client.streamable_http import streamablehttp_client as _client
from mcp.client.session import ClientSession


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
async def http_server(tmp_path):
    proj = tmp_path / "p" / "demo"
    proj.mkdir(parents=True)
    (proj / "hello.txt").write_text("bonjour http\n")
    config = load_config(write_config(tmp_path / "cfg", proj, tmp_path / "audit.log"))
    config.policies.mode = "safe"
    token = "T" * 43
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(build_http_app(config, token), host="127.0.0.1", port=port,
                                           log_level="warning", access_log=False, lifespan="on"))
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.05)
    yield {"base": f"http://127.0.0.1:{port}", "token": token, "proj": proj}
    server.should_exit = True
    await task


def _post_status(url: str) -> int:
    req = urllib.request.Request(url, data=b"{}", method="POST", headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


async def test_wrong_secret_is_404(http_server):
    for path in ("/mcp", "/nope/mcp", "/" + "T" * 42 + "/mcp", "/"):
        assert await asyncio.to_thread(_post_status, http_server["base"] + path) == 404, path


async def test_mcp_over_http_safe_mode(http_server):
    url = f"{http_server['base']}/{http_server['token']}/mcp"
    async with _client(url) as streams:
        read, write = streams[0], streams[1]
        async with ClientSession(read, write) as session:
            await session.initialize()
            names = {t.name for t in (await session.list_tools()).tools}
            assert "read_file" in names and "write_file" not in names and "run_tests" not in names
            res = await session.call_tool("read_file", {"host": "local-sh",
                                                        "path": str(http_server["proj"] / "hello.txt")})
            assert "bonjour http" in res.content[0].text


async def test_tunnel_url_parsing(tmp_path, monkeypatch):
    fake = tmp_path / "cloudflared"
    fake.write_text("#!/bin/sh\necho 'INF Requesting new quick Tunnel' >&2\n"
                    "echo 'INF |  https://calm-river-demo-test.trycloudflare.com  |' >&2\nexec sleep 30\n")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    proc, url = await _start_tunnel(8765)
    try:
        assert url == "https://calm-river-demo-test.trycloudflare.com"
    finally:
        proc.kill()
        await proc.wait()
