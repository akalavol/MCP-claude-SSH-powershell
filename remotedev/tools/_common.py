"""Briques de scripts partagées par les outils (sh et PowerShell)."""

from __future__ import annotations

from ..config import HostConfig
from ..runtime import ps_quote, sh_quote
from ..security.errors import ToolError

PRUNE_DIRS = [".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache",
              ".pytest_cache", "dist", "build", ".next", "target", "bin", "obj"]


def q(host: HostConfig, s: str) -> str:
    return sh_quote(s) if host.is_posix_shell else ps_quote(s)


def ps_array(items: list[str]) -> str:
    return "@(" + ", ".join(ps_quote(i) for i in items) + ")"


def guard(host: HostConfig, path: str, mode: str, var: str = "P") -> str:
    """Ligne de script qui résout `path` côté cible et le place dans $var (ou échoue)."""
    if host.is_posix_shell:
        return f"{var}=$(rd_guard {sh_quote(path)} {mode}) || exit $?\n"
    return f"${var} = Rd-Guard {ps_quote(path)} {ps_quote(mode)}\n"


def run_argv(host: HostConfig, argv: list[str], cwd_var: str | None = "P", check: bool = False) -> str:
    """Exécute une commande (liste d'arguments, jamais une chaîne) dans le dossier $cwd_var.
    check=True : arrête le script si la commande échoue (pour enchaîner plusieurs étapes)."""
    if host.is_posix_shell:
        cd = f'cd "${cwd_var}" || exit 2\n' if cwd_var else ""
        # 97/98 sont réservés aux gardes de sécurité : un échec de commande ne doit pas s'y confondre.
        stop = ' || { rc=$?; case $rc in 97|98) rc=1 ;; esac; exit $rc; }' if check else ""
        return cd + " ".join(sh_quote(a) for a in argv) + " 2>&1" + stop + "\n"
    cd = f"Set-Location -LiteralPath ${cwd_var}\n" if cwd_var else ""
    line = f"Rd-Exec {ps_quote(argv[0])} {ps_array(argv[1:]) if argv[1:] else '@()'}\n"
    if check:
        line += ("if ($global:RD_RC -ne 0) { $__c = $global:RD_RC; if ($__c -eq 97 -or $__c -eq 98) { $__c = 1 }; "
                 f"Rd-Fail $__c ('échec : ' + {ps_quote(argv[0])}) }}\n")
    return cd + line


def run_trusted(host: HostConfig, command: str, cwd_var: str = "P") -> str:
    """Commande textuelle venant de la configuration (jamais du modèle)."""
    if host.is_posix_shell:
        return f'cd "${cwd_var}" || exit 2\n{{ {command}\n}} 2>&1\n'
    return f"Set-Location -LiteralPath ${cwd_var}\nRd-Shell {ps_quote(command)}\n"


def fail_on_error(res, what: str) -> None:
    if res.exit_code != 0:
        msg = (res.stderr.strip() or res.stdout.strip() or f"exit_code={res.exit_code}")[:2000]
        raise ToolError(f"{what} : {msg}")


PS_WALK = r"""
$RdPrune = @(__PRUNE__)
function Rd-Walk([string]$Dir, [int]$Depth, [int]$Max, [System.Collections.ArrayList]$Acc) {
  foreach ($it in @(Get-ChildItem -LiteralPath $Dir -Force -ErrorAction SilentlyContinue | Sort-Object Name)) {
    if ($Acc.Count -ge $Max) { return }
    [void]$Acc.Add($it)
    $isLink = ($it.LinkType -eq 'SymbolicLink' -or $it.LinkType -eq 'Junction')
    if ($it.PSIsContainer -and -not $isLink -and $Depth -gt 1 -and ($RdPrune -notcontains $it.Name)) {
      Rd-Walk $it.FullName ($Depth - 1) $Max $Acc
    }
  }
}
function Rd-Rel([string]$Base, [string]$Full) { return $Full.Substring($Base.Length).TrimStart([char]'\', [char]'/') }
""".replace("__PRUNE__", ", ".join(ps_quote(d) for d in PRUNE_DIRS))
