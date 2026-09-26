"""Backend local : exécute sur la machine du MCP. Sert surtout aux tests."""

from __future__ import annotations

from ..config import HostConfig
from .base import PWSH_ARGS, Backend, ExecResult, local_pwsh, ps_stdin, run_process


class LocalBackend(Backend):
    def __init__(self, host: HostConfig):
        self.host = host

    async def run(self, script: str, stdin: bytes | None = None, timeout: int = 60) -> ExecResult:
        if self.host.is_posix_shell:
            return await run_process(["sh", "-c", script], stdin, timeout)
        return await run_process([local_pwsh(), *PWSH_ARGS], ps_stdin(script, stdin), timeout)
