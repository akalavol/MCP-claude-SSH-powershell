"""Test de connexion aux machines (utilisé par `--check` et la mini-interface)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from .backends import get_backend
from .config import Config, HostConfig


@dataclass
class HostHealth:
    name: str
    ok: bool
    detail: str
    seconds: float


async def check_host(host: HostConfig, timeout: int = 20) -> HostHealth:
    script = ('echo "$(id -un)@$(hostname)"\n' if host.is_posix_shell
              else "Write-Output ([Environment]::UserName + '@' + [Environment]::MachineName)\n")
    try:
        res = await get_backend(host).run(script, timeout=timeout)
    except Exception as exc:  # binaire ssh/pwsh absent, etc.
        return HostHealth(host.name, False, f"{type(exc).__name__}: {exc}", 0.0)
    if res.ok:
        return HostHealth(host.name, True, res.stdout.strip().splitlines()[-1] if res.stdout.strip() else "ok",
                          res.duration)
    detail = "timeout" if res.timed_out else (res.stderr.strip().splitlines() or [f"exit {res.exit_code}"])[-1]
    return HostHealth(host.name, False, detail[:200], res.duration)


async def check_all(config: Config) -> list[HostHealth]:
    return list(await asyncio.gather(*(check_host(h) for h in config.hosts.values())))
