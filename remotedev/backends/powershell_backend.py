"""Backend WinRM (PowerShell Remoting) : `Invoke-Command -ComputerName` depuis le
PowerShell local (pwsh 7, ou Windows PowerShell 5.1 à défaut).

Le script distant est transporté en base64 (jamais interpolé dans du code), les
données via -ArgumentList. Sortie, erreurs et code retour reviennent dans un objet,
car Invoke-Command ne propage pas les codes de sortie.

Limites : sans domaine AD, WinRM exige TrustedHosts/HTTPS et des identifiants
non interactifs, ce que ce backend ne gère pas. Préférer PowerShell 7 over SSH
(backend: ssh + os: windows).
"""

from __future__ import annotations

import base64

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
        return "\n".join([
            f"$__code = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{code}'))",
            "$__p = @{ " + "; ".join(params) + " }",
            "$__r = Invoke-Command @__p -ArgumentList $__code, $global:RdInput -ScriptBlock {",
            "  param($__code, $__in)",
            "  $global:RdInput = $__in",
            "  $global:RD_WINRM = $true",
            "  $global:RD_ERRBUF = New-Object System.Text.StringBuilder",
            "  $__out = . ([scriptblock]::Create($__code)) 2>&1 | Out-String -Width 8192",
            "  [pscustomobject]@{ Out = $__out; Err = $global:RD_ERRBUF.ToString(); Rc = [int]$global:RD_RC }",
            "}",
            "[Console]::Out.Write($__r.Out)",
            "[Console]::Error.Write($__r.Err)",
            "exit $__r.Rc",
        ])

    async def run(self, script: str, stdin: bytes | None = None, timeout: int = 60) -> ExecResult:
        return await run_process(
            [self.local_pwsh, *PWSH_ARGS], ps_stdin(self.wrapper(script), stdin), timeout
        )
