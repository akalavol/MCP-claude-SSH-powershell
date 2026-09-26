"""Backend WinRM (PowerShell Remoting) : `Invoke-Command -ComputerName` depuis le
PowerShell local (pwsh 7, ou Windows PowerShell 5.1 à défaut).

Le script distant est transporté en base64 (jamais interpolé dans du code), les
données via -ArgumentList. Sortie, erreurs et code retour reviennent dans un objet,
car Invoke-Command ne propage pas les codes de sortie.

Identifiants : compte Windows courant (auth: default) ou `user` + mot de passe
enregistré via l'interface (auth: password, chiffré DPAPI). Sans domaine AD, la
cible doit en plus être dans TrustedHosts, ou joignable en HTTPS (use_ssl).
"""

from __future__ import annotations

import base64

from .. import credentials
from ..config import HostConfig
from .base import PWSH_ARGS, Backend, ExecResult, ps_stdin, run_process
from .base import local_pwsh as default_pwsh


def _ps_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


class WinRMBackend(Backend):
    def __init__(self, host: HostConfig, local_pwsh: str | None = None):
        self.host = host
        self.local_pwsh = local_pwsh or default_pwsh()

    def wrapper(self, script: str) -> str:
        h = self.host
        code = base64.b64encode(script.encode("utf-8")).decode("ascii")
        params = [f"ComputerName = {_ps_literal(h.host or h.ssh_alias or '')}", "ErrorAction = 'Stop'"]
        if h.winrm.port:
            params.append(f"Port = {int(h.winrm.port)}")
        if h.winrm.use_ssl:
            params.append("UseSSL = $true")
        if h.winrm.authentication:
            params.append(f"Authentication = {_ps_literal(h.winrm.authentication)}")
        if h.winrm.configuration_name:
            params.append(f"ConfigurationName = {_ps_literal(h.winrm.configuration_name)}")
        cred: list[str] = []
        if h.auth == "password":
            # Le mot de passe reste chiffré (DPAPI) jusque dans ce processus PowerShell.
            blob = base64.b64encode(h.password_blob()).decode("ascii")
            entropy = base64.b64encode(credentials._ENTROPY).decode("ascii")
            cred = [
                "try { Add-Type -AssemblyName System.Security -ErrorAction Stop } catch { }",
                f"$__pw = [Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String('{blob}'), "
                f"[Convert]::FromBase64String('{entropy}'), 'CurrentUser')",
                "$__sec = ConvertTo-SecureString ([Text.Encoding]::UTF8.GetString($__pw)) -AsPlainText -Force",
                f"$__cred = New-Object System.Management.Automation.PSCredential({_ps_literal(h.user or '')}, $__sec)",
                "Remove-Variable __pw",
            ]
            params.append("Credential = $__cred")
        return "\n".join([
            *cred,
            f"$__code = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{code}'))",
            "$__p = @{ " + "; ".join(params) + " }",
            # Erreur de connexion : message en clair (sinon PowerShell l'émet en CLIXML sur stderr).
            "try {",
            "$__r = Invoke-Command @__p -ArgumentList $__code, $global:RdInput -ScriptBlock {",
            "  param($__code, $__in)",
            "  $global:RdInput = $__in",
            "  $global:RD_WINRM = $true",
            "  $global:RD_ERRBUF = New-Object System.Text.StringBuilder",
            "  $__out = . ([scriptblock]::Create($__code)) 2>&1 | Out-String -Width 8192",
            "  [pscustomobject]@{ Out = $__out; Err = $global:RD_ERRBUF.ToString(); Rc = [int]$global:RD_RC }",
            "}",
            "} catch {",
            "  $__m = $_.Exception.Message -replace '<[^>]+>', '' -replace '\\s+', ' '",
            "  $__m = $__m -replace '^.*?(message d.erreur suivant|following error message)\\s*:\\s*', ''",
            "  [Console]::Error.Write('WinRM : ' + $__m.Trim())",
            "  exit 1",
            "}",
            "[Console]::Out.Write($__r.Out)",
            "[Console]::Error.Write($__r.Err)",
            "exit $__r.Rc",
        ])

    async def run(self, script: str, stdin: bytes | None = None, timeout: int = 60) -> ExecResult:
        return await run_process(
            [self.local_pwsh, *PWSH_ARGS], ps_stdin(self.wrapper(script), stdin), timeout
        )
