"""Filtrage des chemins.

Deux couches :
1. contrôle lexical local (rapide, messages clairs) ;
2. garde exécutée côté cible, sur le chemin *résolu* (symlinks, jonctions), dans le
   même script que l'opération. Le contrôle lexical seul est contournable par un
   lien symbolique placé dans le projet.
"""

from __future__ import annotations

import fnmatch
import ntpath
import posixpath
import re

from ..config import HostConfig, Policies
from .errors import SecretDenied, SecurityDenied

_WIN_FORBIDDEN_CHARS = re.compile(r'[<>"|?*\x00-\x1f]')
_WIN_SHORTNAME = re.compile(r"~\d")


def _within(path: str, root: str, windows: bool) -> bool:
    sep = "\\" if windows else "/"
    if windows:
        path, root = path.lower(), root.lower()
    return path == root or path.startswith(root.rstrip(sep) + sep)


def _glob_match(path: str, pattern: str, windows: bool) -> bool:
    if windows:
        return fnmatch.fnmatch(path.lower(), pattern.lower())
    return fnmatch.fnmatchcase(path, pattern)


def is_secret_name(name: str, policies: Policies, windows: bool) -> bool:
    return any(_glob_match(name, p, windows) for p in policies.secret_patterns)


def denied_patterns(host: HostConfig, policies: Policies) -> list[str]:
    if host.is_windows:
        return [host.normpath(p) for p in policies.denied_paths_windows]
    return list(policies.denied_paths_posix)


def check_path(host: HostConfig, policies: Policies, path: str, mode: str = "read") -> str:
    """Contrôle lexical. mode : read | write | list. Retourne le chemin normalisé."""
    if not isinstance(path, str) or not path.strip():
        raise SecurityDenied("chemin vide")
    if any(c in path for c in ("\x00", "\n", "\r")):
        raise SecurityDenied("caractère interdit dans le chemin")
    if path.lstrip().startswith("~"):
        raise SecurityDenied("'~' non supporté : utiliser un chemin absolu")

    windows = host.is_windows
    if windows:
        raw = path.replace("/", "\\")
        if raw.startswith("\\\\"):
            raise SecurityDenied("chemins UNC / \\\\?\\ interdits")
        drive, rest = ntpath.splitdrive(raw)
        if ":" in rest:
            raise SecurityDenied("flux de données alternatifs (ADS) interdits")
        for comp in rest.split("\\"):
            if comp in ("", ".", ".."):
                continue
            if comp.endswith((".", " ")):
                raise SecurityDenied("composant terminé par '.' ou espace interdit (alias NTFS)")
            if _WIN_SHORTNAME.search(comp):
                raise SecurityDenied("noms courts 8.3 (~1) interdits")
            if _WIN_FORBIDDEN_CHARS.search(comp):
                raise SecurityDenied("caractère interdit dans le chemin Windows")
        norm = ntpath.normpath(raw)
    else:
        norm = posixpath.normpath(path)
        if norm.startswith("//"):
            norm = "/" + norm.lstrip("/")

    if not host.isabs(norm):
        raise SecurityDenied(f"chemin absolu requis : {path!r}")
    if not any(_within(norm, root, windows) for root in host.allowed_paths):
        raise SecurityDenied(f"hors des allowed_paths : {norm}")
    for pat in denied_patterns(host, policies):
        if _glob_match(norm, pat, windows) or _glob_match(norm, pat.rstrip("\\/") + ("\\*" if windows else "/*"), windows):
            raise SecurityDenied(f"chemin système protégé : {norm}")

    base = ntpath.basename(norm) if windows else posixpath.basename(norm)
    if mode != "list" and is_secret_name(base, policies, windows):
        raise SecretDenied()
    if mode == "write" and policies.protect_git_dir:
        parts = norm.lower().split("\\") if windows else norm.split("/")
        if ".git" in parts:
            raise SecurityDenied("écriture dans .git interdite")
    return norm


# --------------------------------------------------------------------------------
# Gardes côté cible
# --------------------------------------------------------------------------------

def _sh_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


def _sh_glob(pattern: str) -> str:
    """Motif de `case` : jokers * ? actifs, tout le reste littéral."""
    return "".join(c if (c.isalnum() or c in "*?/") else "\\" + c for c in pattern)


def _ps_quote(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def posix_guard(host: HostConfig, policies: Policies) -> str:
    roots = " ".join(_sh_quote(r) for r in host.allowed_paths)
    denied: list[str] = []
    for p in denied_patterns(host, policies):
        g = _sh_glob(p.rstrip("/"))
        denied += [g, g + "/*"]
    secrets = "|".join(_sh_glob(p) for p in policies.secret_patterns) or "''"
    denied_case = (
        f'  case "$_r" in {"|".join(denied)}) echo "RD_DENIED: chemin système protégé" >&2; return 97 ;; esac\n'
        if denied else ""
    )
    git_case = (
        '  if [ "$2" = write ]; then case "$_r" in */.git|*/.git/*) '
        'echo "RD_DENIED: écriture dans .git interdite" >&2; return 97 ;; esac; fi\n'
        if policies.protect_git_dir else ""
    )
    return (
        "rd_guard() {\n"
        '  _r=$(realpath -m -- "$1" 2>/dev/null) || { echo "RD_DENIED: chemin non résolu" >&2; return 97; }\n'
        "  _ok=0\n"
        f"  for _root in {roots}; do\n"
        '    _rr=$(realpath -m -- "$_root" 2>/dev/null) || continue\n'
        '    case "$_r" in "$_rr"|"$_rr"/*) _ok=1 ;; esac\n'
        "  done\n"
        '  [ "$_ok" = 1 ] || { echo "RD_DENIED: hors des allowed_paths (après résolution des liens)" >&2; return 97; }\n'
        + denied_case
        + f'  if [ "$2" != list ]; then case "${{_r##*/}}" in {secrets}) echo "RD_SECRET" >&2; return 98 ;; esac; fi\n'
        + git_case
        + "  printf '%s\\n' \"$_r\"\n"
        "}\n"
    )


def powershell_guard(host: HostConfig, policies: Policies) -> str:
    roots = ", ".join(_ps_quote(r) for r in host.allowed_paths)
    denied = ", ".join(_ps_quote(p) for p in denied_patterns(host, policies))
    secrets = ", ".join(_ps_quote(p) for p in policies.secret_patterns)
    protect = "$true" if policies.protect_git_dir else "$false"
    return f"""
$RdRoots = @({roots})
$RdDenied = @({denied})
$RdSecrets = @({secrets})
$RdProtectGit = {protect}
function Rd-Guard([string]$Path, [string]$Mode) {{
  $sep = [IO.Path]::DirectorySeparatorChar
  $cmp = [StringComparison]::Ordinal
  if ($env:OS -eq 'Windows_NT') {{ $cmp = [StringComparison]::OrdinalIgnoreCase }}
  $full = [IO.Path]::GetFullPath($Path)
  if ($full.Length -gt 3) {{ $full = $full.TrimEnd($sep) }}
  $root = $null
  foreach ($r in $RdRoots) {{
    $rf = [IO.Path]::GetFullPath($r).TrimEnd($sep)
    if ($full.Equals($rf, $cmp) -or $full.StartsWith($rf + $sep, $cmp)) {{ $root = $rf; break }}
  }}
  if (-not $root) {{ Rd-Fail 97 'hors des allowed_paths' }}
  foreach ($d in $RdDenied) {{
    if ($full -like $d -or $full -like ($d.TrimEnd($sep) + $sep + '*')) {{ Rd-Fail 97 'chemin système protégé' }}
  }}
  $cur = $full
  while ($cur -and $cur.Length -ge $root.Length) {{
    if (Test-Path -LiteralPath $cur) {{
      $it = Get-Item -LiteralPath $cur -Force
      if ($it.LinkType -eq 'SymbolicLink' -or $it.LinkType -eq 'Junction') {{ Rd-Fail 97 ('lien symbolique / jonction refusé : ' + $cur) }}
    }}
    if ($cur.Length -eq $root.Length) {{ break }}
    $cur = [IO.Path]::GetDirectoryName($cur)
  }}
  if ($Mode -ne 'list') {{
    $leaf = [IO.Path]::GetFileName($full)
    foreach ($s in $RdSecrets) {{ if ($leaf -like $s) {{ Rd-Fail 98 'SECRET' }} }}
  }}
  if ($Mode -eq 'write' -and $RdProtectGit) {{
    if ($full -like ('*' + $sep + '.git') -or $full -like ('*' + $sep + '.git' + $sep + '*')) {{ Rd-Fail 97 'écriture dans .git interdite' }}
  }}
  return $full
}}
"""
