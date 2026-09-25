"""Exécution d'un script sur une cible, indépendamment du transport."""

from __future__ import annotations

import asyncio
import base64
import shutil
import sys
import time
from dataclasses import dataclass
from functools import lru_cache

# Codes de sortie réservés émis par les gardes des scripts distants.
RC_DENIED = 97
RC_SECRET = 98
RC_TIMEOUT = 124

# Bootstrap PowerShell : ligne 1 de stdin = script (base64 UTF-8), ligne 2 = données (base64).
# Passer le script par stdin évite la limite de 8191 caractères de cmd.exe (shell par
# défaut d'OpenSSH sous Windows) et tout problème de quoting.
PS_BOOTSTRAP = (
    "$ErrorActionPreference='Stop';"
    "$__l=[Console]::In.ReadLine();"
    "$global:RdInput=[Console]::In.ReadLine();"
    ". ([scriptblock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($__l))))"
)
PS_BOOTSTRAP_ENCODED = base64.b64encode(PS_BOOTSTRAP.encode("utf-16-le")).decode("ascii")
PWSH_ARGS = ["-NoProfile", "-NonInteractive", "-NoLogo", "-EncodedCommand", PS_BOOTSTRAP_ENCODED]


@lru_cache(maxsize=1)
def local_pwsh() -> str:
    """PowerShell de la machine du MCP : pwsh (7) si installé, sinon Windows PowerShell 5.1."""
    if shutil.which("pwsh"):
        return "pwsh"
    if sys.platform == "win32" and shutil.which("powershell"):
        return "powershell"
    return "pwsh"  # l'erreur « introuvable » mentionnera pwsh


@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


def ps_stdin(script: str, data: bytes | None) -> bytes:
    lines = [base64.b64encode(script.encode("utf-8")), base64.b64encode(data or b"")]
    return b"\n".join(lines) + b"\n"


async def run_process(argv: list[str], stdin: bytes | None, timeout: int) -> ExecResult:
    """Lance un processus local. stdin n'hérite JAMAIS du flux stdio MCP."""
    start = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(stdin), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        out, err = await proc.communicate()
        return ExecResult(
            RC_TIMEOUT,
            out.decode("utf-8", "replace"),
            err.decode("utf-8", "replace") + f"\n[timeout après {timeout}s]",
            time.monotonic() - start,
            timed_out=True,
        )
    return ExecResult(
        proc.returncode if proc.returncode is not None else -1,
        out.decode("utf-8", "replace"),
        err.decode("utf-8", "replace"),
        time.monotonic() - start,
    )


class Backend:
    async def run(self, script: str, stdin: bytes | None = None, timeout: int = 60) -> ExecResult:
        raise NotImplementedError
