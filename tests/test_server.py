"""Bout en bout : le serveur réel, via le protocole MCP stdio."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from conftest import ROOT, write_config

pytestmark = pytest.mark.asyncio

try:
    from mcp.client.session import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
except ImportError:  # pragma: no cover
    pytest.skip("client MCP indisponible", allow_module_level=True)


def _attr(obj, snake: str, camel: str):
    """mcp 2.x : snake_case ; mcp 1.x : camelCase."""
    return getattr(obj, snake) if hasattr(obj, snake) else getattr(obj, camel)


async def _session_tools(tmp_path: Path, mode: str, call=None):
    proj = tmp_path / "p" / "demo"
    proj.mkdir(parents=True)
    (proj / "hello.txt").write_text("bonjour\n")
    cdir = write_config(tmp_path / "cfg", proj, tmp_path / "audit.log", mode=mode)
    params = StdioServerParameters(
        command=sys.executable, args=[str(ROOT / "server.py")],
        env={**os.environ, "REMOTEDEV_CONFIG_DIR": str(cdir)},
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = {t.name: t for t in (await session.list_tools()).tools}
            result = await call(session, proj) if call else None
            return tools, result


async def test_dev_mode_exposes_dev_tools(tmp_path):
    async def call(session, proj):
        return await session.call_tool("read_file", {"host": "local-sh", "path": str(proj / "hello.txt")})

    tools, result = await _session_tools(tmp_path, "dev", call)
    assert {"read_file", "write_file", "run_tests", "git_status", "host_list"} <= set(tools)
    assert _attr(tools["read_file"].annotations, "read_only_hint", "readOnlyHint") is True
    assert _attr(tools["write_file"].annotations, "destructive_hint", "destructiveHint") is True
    assert not _attr(result, "is_error", "isError")
    assert "bonjour" in result.content[0].text


async def test_safe_mode_hides_dev_tools(tmp_path):
    async def call(session, proj):
        return await session.call_tool("read_file", {"host": "local-sh", "path": "/etc/passwd"})

    tools, result = await _session_tools(tmp_path, "safe", call)
    assert "read_file" in tools
    assert not ({"write_file", "patch_file", "run_tests", "git_pull"} & set(tools))
    assert _attr(result, "is_error", "isError") and "ACCESS DENIED" in result.content[0].text
