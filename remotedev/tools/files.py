"""Outils fichiers : lecture, écriture atomique, patch, recherche."""

from __future__ import annotations

import base64
import codecs
import re

from ..runtime import rt, sh_quote, ps_quote, tool
from ..security.errors import SecurityDenied, ToolError
from ..security.path_filter import is_secret_name
from ..security.validator import clamp
from ._common import PRUNE_DIRS, PS_WALK, fail_on_error, guard

_GLOB_ARG = re.compile(r"^[A-Za-z0-9._*?\-\[\]{},/]{1,100}$")


def _decode(data: bytes) -> tuple[str | None, str]:
    """(texte, encodage) ; texte None si binaire."""
    if data.startswith(codecs.BOM_UTF8):
        return data[3:].decode("utf-8", "replace"), "utf-8-sig"
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return data.decode("utf-16", "replace"), "utf-16"
    if b"\x00" in data[:8192]:
        return None, "binary"
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return data.decode("latin-1"), "latin-1"


def _encode(text: str, encoding: str) -> bytes:
    if encoding == "utf-8-sig":
        return codecs.BOM_UTF8 + text.encode("utf-8")
    if encoding == "utf-16":
        return text.encode("utf-16")
    if encoding == "latin-1":
        return text.encode("latin-1", "strict")
    return text.encode("utf-8")


async def read_bytes(host_name: str, path: str, max_bytes: int) -> tuple[int, bytes, str]:
    """Lecture brute (sans masquage). Retourne (taille totale, octets lus, chemin résolu)."""
    r = rt()
    h = r.host(host_name)
    p = r.path(h, path, "read")
    if h.is_posix_shell:
        body = guard(h, p, "read") + (
            '[ -f "$P" ] || { echo "fichier introuvable : $P" >&2; exit 2; }\n'
            'printf "%s\\n" "$P"\n'
            'stat -c %s -- "$P"\n'
            f'head -c {int(max_bytes)} -- "$P" | base64 | tr -d "\\n"\n'
        )
    else:
        body = guard(h, p, "read") + f"""
if (-not (Test-Path -LiteralPath $P -PathType Leaf)) {{ Rd-Fail 2 ('fichier introuvable : ' + $P) }}
$len = (Get-Item -LiteralPath $P -Force).Length
$n = [int][Math]::Min([int64]$len, [int64]{int(max_bytes)})
$buf = New-Object byte[] $n
$fs = [IO.File]::Open($P, 'Open', 'Read', 'ReadWrite')
try {{ $read = 0; while ($read -lt $n) {{ $k = $fs.Read($buf, $read, $n - $read); if ($k -le 0) {{ break }}; $read += $k }} }} finally {{ $fs.Dispose() }}
Write-Output $P
Write-Output ([string]$len)
Write-Output ([Convert]::ToBase64String($buf, 0, $read))
"""
    res = await r.run(h, body)
    fail_on_error(res, "lecture impossible")
    lines = res.stdout.strip().splitlines()
    if len(lines) < 2:
        raise ToolError(f"réponse inattendue : {res.stdout[:200]!r}")
    resolved, size = lines[0].strip(), int(lines[1].strip())
    data = base64.b64decode("".join("".join(lines[2:]).split()))
    return size, data, resolved


async def write_bytes(host_name: str, path: str, data: bytes, create_dirs: bool) -> str:
    r = rt()
    h = r.host(host_name)
    p = r.path(h, path, "write")
    if len(data) > r.policies.limits.max_write_bytes:
        raise SecurityDenied(f"contenu trop gros ({len(data)} > {r.policies.limits.max_write_bytes} octets)")
    if h.is_posix_shell:
        mk = 'mkdir -p -- "$D"' if create_dirs else '{ echo "dossier parent absent : $D (create_dirs=true pour le créer)" >&2; exit 2; }'
        body = guard(h, p, "write") + (
            'D=$(dirname -- "$P")\n'
            f'[ -d "$D" ] || {mk}\n'
            'D=$(rd_guard "$D" list) || exit $?\n'
            '[ -d "$P" ] && { echo "est un dossier : $P" >&2; exit 2; }\n'
            'T=$(mktemp "$D/.rd-tmp.XXXXXX") || exit 1\n'
            'cat > "$T" || { rm -f -- "$T"; exit 1; }\n'
            '[ -f "$P" ] && chmod --reference="$P" -- "$T" 2>/dev/null\n'
            'mv -f -- "$T" "$P" || { rm -f -- "$T"; exit 1; }\n'
            'echo "$P"\n'
        )
    else:
        mk = ("[void][IO.Directory]::CreateDirectory($D)" if create_dirs
              else "Rd-Fail 2 ('dossier parent absent : ' + $D + ' (create_dirs=true pour le créer)')")
        body = guard(h, p, "write") + f"""
$D = [IO.Path]::GetDirectoryName($P)
if (-not (Test-Path -LiteralPath $D -PathType Container)) {{ {mk} }}
$D = Rd-Guard $D 'list'
if (Test-Path -LiteralPath $P -PathType Container) {{ Rd-Fail 2 ('est un dossier : ' + $P) }}
$bytes = [Convert]::FromBase64String($global:RdInput)
$T = Join-Path $D ('.rd-tmp.' + [Guid]::NewGuid().ToString('N'))
[IO.File]::WriteAllBytes($T, $bytes)
if (Test-Path -LiteralPath $P) {{ [IO.File]::Replace($T, $P, [NullString]::Value) }} else {{ [IO.File]::Move($T, $P) }}
Write-Output $P
"""
    res = await r.run(h, body, stdin=data)
    fail_on_error(res, "écriture impossible")
    return res.stdout.strip().splitlines()[-1]


@tool("read")
async def list_files(host: str, path: str, recursive: bool = False, max_depth: int = 3) -> str:
    """Liste un dossier (type, taille, date, chemin relatif). recursive=true descend jusqu'à max_depth,
    sans entrer dans .git, node_modules, .venv, dist, build..."""
    r = rt()
    h = r.host(host)
    r.require(h, "read")
    p = r.path(h, path, "list")
    depth = clamp(max_depth, 1, 10) if recursive else 1
    limit = r.policies.limits.max_list_entries
    if h.is_posix_shell:
        prune = " -o ".join(f"-name {sh_quote(d)}" for d in PRUNE_DIRS)
        body = guard(h, p, "list") + (
            '[ -d "$P" ] || { echo "pas un dossier : $P" >&2; exit 2; }\n'
            'cd "$P" || exit 2\n'
            f"find . -mindepth 1 -maxdepth {depth} -type d \\( {prune} \\) "
            "-printf '%y %10s %TY-%Tm-%Td %TH:%TM %P/ [non parcouru]\\n' -prune "
            "-o -printf '%y %10s %TY-%Tm-%Td %TH:%TM %P\\n' "
            f"| sort -k5 | head -n {limit + 1}\n"
        )
    else:
        body = PS_WALK + guard(h, p, "list") + f"""
if (-not (Test-Path -LiteralPath $P -PathType Container)) {{ Rd-Fail 2 ('pas un dossier : ' + $P) }}
$acc = New-Object System.Collections.ArrayList
Rd-Walk $P {depth} {limit + 1} $acc
foreach ($it in $acc) {{
  $t = 'f'; if ($it.PSIsContainer) {{ $t = 'd' }}; if ($it.LinkType) {{ $t = 'l' }}
  $len = 0; if (-not $it.PSIsContainer) {{ $len = $it.Length }}
  $rel = Rd-Rel $P $it.FullName
  if ($it.PSIsContainer -and ($RdPrune -contains $it.Name)) {{ $rel = $rel + '/ [non parcouru]' }}
  Write-Output ('{{0}} {{1,10}} {{2:yyyy-MM-dd HH:mm}} {{3}}' -f $t, $len, $it.LastWriteTime, $rel)
}}
"""
    res = await r.run(h, body)
    fail_on_error(res, "listing impossible")
    lines = res.stdout.splitlines()
    note = ""
    if len(lines) > limit:
        lines = lines[:limit]
        note = f"\n[tronqué à {limit} entrées]"
    return f"{p}\n(type taille date chemin ; d=dossier f=fichier l=lien)\n" + "\n".join(lines) + note


@tool("read")
async def read_file(host: str, path: str, start_line: int = 1, max_lines: int = 2000) -> str:
    """Lit un fichier texte (les fichiers secrets sont refusés). start_line/max_lines pour paginer."""
    r = rt()
    h = r.host(host)
    r.require(h, "read")
    size, data, resolved = await read_bytes(host, path, r.policies.limits.max_read_bytes)
    text, enc = _decode(data)
    if text is None:
        return f"{resolved} : fichier binaire ({size} octets), contenu non affiché."
    lines = text.splitlines()
    start = clamp(start_line, 1, max(1, len(lines)))
    count = clamp(max_lines, 1, 20000)
    chunk = lines[start - 1:start - 1 + count]
    header = f"{resolved} ({size} octets, {enc}, {len(lines)} lignes"
    if size > len(data):
        header += f", lecture limitée aux {len(data)} premiers octets"
    if start > 1 or start - 1 + count < len(lines):
        header += f", lignes {start}-{start + len(chunk) - 1}"
    header += ")"
    return header + "\n" + rt().clip("\n".join(chunk), 10**9)


@tool("read")
async def file_info(host: str, path: str) -> str:
    """Métadonnées d'un fichier ou dossier (type, taille, date, droits)."""
    r = rt()
    h = r.host(host)
    r.require(h, "read")
    p = r.path(h, path, "list")
    if h.is_posix_shell:
        body = guard(h, p, "list") + (
            '[ -e "$P" ] || { echo "introuvable : $P" >&2; exit 2; }\n'
            'stat -c "chemin: %n%ntype: %F%ntaille: %s%nmodifié: %y%ndroits: %A%nproprio: %U:%G" -- "$P"\n'
        )
    else:
        body = guard(h, p, "list") + """
if (-not (Test-Path -LiteralPath $P)) { Rd-Fail 2 ('introuvable : ' + $P) }
$it = Get-Item -LiteralPath $P -Force
Write-Output ('chemin: ' + $it.FullName)
Write-Output ('type: ' + $(if ($it.PSIsContainer) { 'dossier' } else { 'fichier' }))
if (-not $it.PSIsContainer) { Write-Output ('taille: ' + $it.Length) }
Write-Output ('modifié: ' + $it.LastWriteTime.ToString('s'))
Write-Output ('attributs: ' + $it.Attributes)
"""
    res = await r.run(h, body)
    fail_on_error(res, "file_info impossible")
    return res.stdout.strip()


@tool("dev", read_only=False, destructive=True)
async def write_file(host: str, path: str, content: str, create_dirs: bool = False) -> str:
    """Écrit (remplace) un fichier texte UTF-8 de façon atomique. Refusé pour les secrets et .git."""
    r = rt()
    h = r.host(host)
    r.require(h, "dev")
    resolved = await write_bytes(host, path, content.encode("utf-8"), create_dirs)
    return f"écrit : {resolved} ({len(content.encode('utf-8'))} octets)"


@tool("dev", read_only=False, destructive=True)
async def patch_file(host: str, path: str, old_string: str, new_string: str, replace_all: bool = False) -> str:
    """Remplace old_string par new_string dans un fichier. old_string doit être unique
    (sauf replace_all=true). Gère les fins de ligne CRLF et l'encodage existant."""
    r = rt()
    h = r.host(host)
    r.require(h, "dev")
    r.path(h, path, "write")
    if not old_string:
        raise ToolError("old_string vide : utiliser write_file pour créer un fichier")
    limit = r.policies.limits.max_write_bytes
    size, data, resolved = await read_bytes(host, path, limit + 1)
    if size > limit:
        raise SecurityDenied(f"fichier trop gros pour patch_file ({size} octets)")
    text, enc = _decode(data)
    if text is None:
        raise ToolError("fichier binaire : patch refusé")
    old, new = old_string, new_string
    if old not in text and "\r\n" in text and "\r\n" not in old:
        old, new = old.replace("\n", "\r\n"), new.replace("\n", "\r\n")
    count = text.count(old)
    if count == 0:
        raise ToolError("old_string introuvable dans le fichier (relire le fichier : espaces, indentation, fins de ligne)")
    if count > 1 and not replace_all:
        raise ToolError(f"old_string apparaît {count} fois : ajouter du contexte pour le rendre unique, ou replace_all=true")
    patched = text.replace(old, new) if replace_all else text.replace(old, new, 1)
    try:
        payload = _encode(patched, enc)
    except UnicodeEncodeError:
        raise ToolError(f"le nouveau texte n'est pas encodable en {enc}")
    await write_bytes(host, path, payload, create_dirs=False)
    return f"patché : {resolved} ({count if replace_all else 1} remplacement(s))"


@tool("read")
async def search_files(
    host: str, project_path: str, query: str, mode: str = "content", glob: str | None = None,
    regex: bool = False, max_results: int = 100,
) -> str:
    """Recherche dans un projet. mode="content" : texte (fixe, ou regex=true) dans les fichiers,
    filtrables par glob (ex. "*.py"). mode="name" : fichiers dont le nom correspond au glob `query`.
    Les fichiers secrets sont exclus."""
    r = rt()
    h = r.host(host)
    r.require(h, "read")
    p = r.project_path(h, project_path)
    if mode not in ("content", "name"):
        raise ToolError("mode doit valoir 'content' ou 'name'")
    if not query or "\n" in query or len(query) > 500:
        raise ToolError("query invalide")
    if glob is not None and not _GLOB_ARG.match(glob):
        raise ToolError("glob invalide")
    if mode == "name" and not _GLOB_ARG.match(query):
        raise ToolError("en mode name, query est un glob (ex. '*config*.py')")
    limit = clamp(max_results, 1, r.policies.limits.max_search_results)
    secrets = r.policies.secret_patterns
    if h.is_posix_shell:
        prune = " -o ".join(f"-name {sh_quote(d)}" for d in PRUNE_DIRS)
        if mode == "name":
            cmd = (f'find . -type d \\( {prune} \\) -prune -o -iname {sh_quote(query)} -print '
                   f"| sed 's|^\\./||' | head -n {limit}\n")
        else:
            excl = " ".join(f"--exclude-dir={sh_quote(d)}" for d in PRUNE_DIRS)
            excl += " " + " ".join(f"--exclude={sh_quote(s)}" for s in secrets)
            inc = f"--include={sh_quote(glob)}" if glob else ""
            flag = "-E" if regex else "-F"
            cmd = (f"grep -rIn --color=never {flag} {excl} {inc} -e {sh_quote(query)} . 2>/dev/null "
                   f"| sed 's|^\\./||' | cut -c1-400 | head -n {limit}\n")
        body = guard(h, p, "list") + 'cd "$P" || exit 2\n' + cmd
    else:
        secret_arr = ", ".join(ps_quote(s) for s in secrets)
        match = "-SimpleMatch" if not regex else ""
        glob_filter = f" -and $it.Name -like {ps_quote(glob)}" if glob else ""
        if mode == "name":
            loop = f"""
foreach ($it in $acc) {{
  if ($it.Name -like {ps_quote(query)}) {{ Write-Output (Rd-Rel $P $it.FullName); $n++; if ($n -ge {limit}) {{ break }} }}
}}"""
        else:
            loop = f"""
$secrets = @({secret_arr})
foreach ($it in $acc) {{
  if ($it.PSIsContainer -or $it.LinkType -or $it.Length -gt 2MB) {{ continue }}
  $skip = $false; foreach ($s in $secrets) {{ if ($it.Name -like $s) {{ $skip = $true }} }}
  if ($skip{" -or -not ($true" + glob_filter + ")" if glob else ""}) {{ continue }}
  foreach ($m in @(Select-String -LiteralPath $it.FullName -Pattern {ps_quote(query)} {match} -ErrorAction SilentlyContinue)) {{
    $line = $m.Line; if ($line.Length -gt 400) {{ $line = $line.Substring(0, 400) }}
    Write-Output ('{{0}}:{{1}}:{{2}}' -f (Rd-Rel $P $it.FullName), $m.LineNumber, $line)
    $n++; if ($n -ge {limit}) {{ break }}
  }}
  if ($n -ge {limit}) {{ break }}
}}"""
        body = PS_WALK + guard(h, p, "list") + f"""
$acc = New-Object System.Collections.ArrayList
Rd-Walk $P 64 50000 $acc
$n = 0
{loop}
"""
    res = await r.run(h, body, timeout=max(r.policies.timeouts.default, 120))
    fail_on_error(res, "recherche impossible")
    out = res.stdout.strip()
    if not out:
        return f"aucun résultat dans {p}"
    # Filet : ne jamais renvoyer de ligne issue d'un fichier secret.
    kept = []
    for line in out.splitlines():
        name = line.split(":", 1)[0].replace("\\", "/").rsplit("/", 1)[-1]
        if is_secret_name(name, r.policies, h.is_windows):
            continue
        kept.append(line)
    suffix = f"\n[limité à {limit} résultats]" if len(kept) >= limit else ""
    return f"{p}\n" + r.clip("\n".join(kept)) + suffix
