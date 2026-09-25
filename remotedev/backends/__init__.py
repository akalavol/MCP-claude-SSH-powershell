"""Routeur : choisit le backend selon la configuration de l'hôte."""

from __future__ import annotations

from ..config import HostConfig
from .base import Backend, ExecResult
from .local_backend import LocalBackend
from .powershell_backend import WinRMBackend
from .ssh_backend import SSHBackend


def get_backend(host: HostConfig) -> Backend:
    if host.backend == "ssh":
        return SSHBackend(host)
    if host.backend == "winrm":
        return WinRMBackend(host)
    if host.backend == "local":
        return LocalBackend(host)
    raise ValueError(f"backend inconnu : {host.backend}")


__all__ = ["Backend", "ExecResult", "get_backend"]
