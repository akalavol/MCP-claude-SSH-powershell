"""Backend OpenSSH : Linux (sh) ou Windows (PowerShell 7 over SSH)."""

from __future__ import annotations

import os
import shlex
import sys
from pathlib import Path

from .. import hostkey
from ..config import HostConfig
from .base import PWSH_ARGS, RC_TIMEOUT, Backend, ExecResult, ps_stdin, run_process

ASKPASS = Path(__file__).resolve().parent.parent / "askpass.cmd"


class SSHBackend(Backend):
    def __init__(self, host: HostConfig, ssh_binary: str = "ssh"):
        self.host = host
        self.ssh_binary = ssh_binary

    def ssh_argv(self) -> list[str]:
        h = self.host
        if h.auth == "password":
            # Mot de passe fourni par askpass (jamais sur la ligne de commande) ; un seul essai.
            auth = ["-o", "BatchMode=no", "-o", "PreferredAuthentications=password,keyboard-interactive",
                    "-o", "PubkeyAuthentication=no", "-o", "NumberOfPasswordPrompts=1"]
        else:
            auth = ["-o", "BatchMode=yes"]   # jamais de prompt mot de passe
        argv = [
            self.ssh_binary,
            *auth,
            "-o", "ConnectTimeout=10",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=3",
            "-T",                            # pas de TTY
        ]
        if h.ssh_alias:
            argv.append(h.ssh_alias)
            return argv
        if h.host_key_sha256:
            # Uniquement la clé épinglée ; guillemets : le chemin peut contenir des espaces.
            kh = h.known_hosts_file().as_posix()
            argv += ["-o", f'UserKnownHostsFile="{kh}"', "-o", "StrictHostKeyChecking=yes",
                     "-o", f"HostKeyAlias={hostkey.alias(h.name)}"]
        if h.port:
            argv += ["-p", str(h.port)]
        if h.key and h.auth != "password":
            argv += ["-i", h.key, "-o", "IdentitiesOnly=yes"]
        if h.user:
            argv += ["-l", h.user]
        argv.append(h.host or "")
        return argv

    def keyscan_binary(self) -> str:
        ssh = Path(self.ssh_binary)
        return str(ssh.with_name("ssh-keyscan" + ssh.suffix)) if ssh.parent != Path(".") else "ssh-keyscan"

    async def ensure_host_key(self) -> None:
        """Épingle la clé d'hôte si host_key_sha256 est renseigné et qu'elle ne l'est pas encore."""
        h = self.host
        expected = h.host_key_sha256
        if not expected:
            return
        path, name = h.known_hosts_file(), hostkey.alias(h.name)
        if hostkey.is_pinned(path, name, expected):
            return
        # host est validé par la config : il ne commence jamais par « - ».
        argv = [self.keyscan_binary(), "-T", "10"] + (["-p", str(h.port)] if h.port else []) + [h.host or ""]
        res = await run_process(argv, None, 20)
        key, seen = hostkey.find_key(res.stdout, expected)
        if key is None:
            if not seen:
                err = (res.stderr.strip().splitlines() or [f"exit {res.exit_code}"])[-1]
                raise RuntimeError(f"clé d'hôte illisible (ssh-keyscan) : {err}")
            raise RuntimeError(f"empreinte refusée : le serveur présente {', '.join(seen)} au lieu de {expected}")
        hostkey.pin(path, name, *key)

    def env(self) -> dict[str, str] | None:
        """Environnement de ssh : askpass en mode mot de passe (rien de secret dedans)."""
        h = self.host
        if h.auth != "password":
            return None
        if sys.platform != "win32":
            raise RuntimeError("mot de passe SSH : uniquement sous Windows (utiliser une clé SSH)")
        h.password_blob()  # erreur claire si aucun mot de passe n'est enregistré
        return {
            **os.environ,
            "SSH_ASKPASS": str(ASKPASS),
            "SSH_ASKPASS_REQUIRE": "force",
            "DISPLAY": os.environ.get("DISPLAY", "remotedev"),
            "RD_ASKPASS_PY": sys.executable,
            "RD_ASKPASS_HOST": h.name,
            "RD_ASKPASS_CONFIG": str(h._config_dir or ""),
        }

    async def run(self, script: str, stdin: bytes | None = None, timeout: int = 60) -> ExecResult:
        env = self.env()
        await self.ensure_host_key()
        if self.host.is_posix_shell:
            # `timeout` distant : le processus distant meurt même si la connexion est coupée.
            remote = f"timeout -k 5 {int(timeout)} sh -c {shlex.quote(script)}"
            res = await run_process(self.ssh_argv() + [remote], stdin, timeout + 10, env)
            if res.exit_code == RC_TIMEOUT:
                res.timed_out = True
                res.stderr += f"\n[timeout distant après {timeout}s]"
            return res
        # Windows : le shell par défaut (cmd ou powershell) ne voit que du base64.
        remote = self.host.ps_exe + " " + " ".join(PWSH_ARGS)
        return await run_process(self.ssh_argv() + [remote], ps_stdin(script, stdin), timeout, env)
