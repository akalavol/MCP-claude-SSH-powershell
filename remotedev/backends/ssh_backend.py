"""Backend OpenSSH : Linux (sh) ou Windows (PowerShell 7 over SSH)."""

from __future__ import annotations

import shlex

from ..config import HostConfig
from .base import PWSH_ARGS, RC_TIMEOUT, Backend, ExecResult, ps_stdin, run_process


class SSHBackend(Backend):
    def __init__(self, host: HostConfig, ssh_binary: str = "ssh"):
        self.host = host
        self.ssh_binary = ssh_binary

    def ssh_argv(self) -> list[str]:
        h = self.host
        argv = [
            self.ssh_binary,
            "-o", "BatchMode=yes",           # jamais de prompt mot de passe
            "-o", "ConnectTimeout=10",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=3",
            "-T",                            # pas de TTY
        ]
        if h.ssh_alias:
            argv.append(h.ssh_alias)
            return argv
        if h.port:
            argv += ["-p", str(h.port)]
        if h.key:
            argv += ["-i", h.key, "-o", "IdentitiesOnly=yes"]
        if h.user:
            argv += ["-l", h.user]
        argv.append(h.host or "")
        return argv

    async def run(self, script: str, stdin: bytes | None = None, timeout: int = 60) -> ExecResult:
        if self.host.is_posix_shell:
            # `timeout` distant : le processus distant meurt même si la connexion est coupée.
            remote = f"timeout -k 5 {int(timeout)} sh -c {shlex.quote(script)}"
            res = await run_process(self.ssh_argv() + [remote], stdin, timeout + 10)
            if res.exit_code == RC_TIMEOUT:
                res.timed_out = True
                res.stderr += f"\n[timeout distant après {timeout}s]"
            return res
        # Windows : le shell par défaut (cmd ou powershell) ne voit que du base64.
        remote = "pwsh " + " ".join(PWSH_ARGS)
        return await run_process(self.ssh_argv() + [remote], ps_stdin(script, stdin), timeout)
