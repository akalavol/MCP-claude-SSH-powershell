"""Outils machine : inventaire, infos système, disque, processus, services."""

from __future__ import annotations

from ..runtime import rt, sh_quote, ps_quote, tool
from ..security.validator import clamp
from ._common import guard


@tool("read")
async def host_list() -> str:
    """Liste les machines autorisées, leur backend, leurs permissions effectives et leurs projets."""
    r = rt()
    lines = [f"mode global : {r.policies.mode.upper()}"]
    for name, h in sorted(r.config.hosts.items()):
        eff = [lvl for lvl in h.permissions if lvl in r.config.mode_levels]
        lines.append(f"\n{name} — {h.os}/{h.backend} ({h.host or h.ssh_alias or 'local'})")
        lines.append(f"  permissions effectives : {', '.join(eff) or 'aucune'}")
        lines.append("  allowed_paths : " + ", ".join(h.allowed_paths))
        if h.projects:
            lines.append("  projets : " + ", ".join(f"{k}={v.path}" for k, v in h.projects.items()))
        if h.docker.enabled:
            lines.append("  docker : activé")
        if h.services.restartable:
            lines.append("  services redémarrables : " + ", ".join(h.services.restartable))
        if h.log_sources:
            lines.append("  sources de logs : " + ", ".join(h.log_sources))
    return "\n".join(lines)


@tool("read")
async def host_info(host: str) -> str:
    """Configuration d'une machine + test de connexion (utilisateur distant, nom d'hôte)."""
    r = rt()
    h = r.host(host)
    r.require(h, "read")
    body = ('echo "connecté en tant que $(id -un) sur $(hostname)"\n' if h.is_posix_shell else
            "Write-Output ('connecté en tant que ' + [Environment]::UserName + ' sur ' + [Environment]::MachineName)\n")
    res = await r.run(h, body, timeout=20)
    conn = res.stdout.strip() if res.ok else f"ÉCHEC : {res.stderr.strip()[:500]}"
    cfg = h.model_dump(exclude={"key"})
    cfg["key"] = "(configurée)" if h.key else None
    return f"{host} : {conn}\nconfiguration : {cfg}"


@tool("read")
async def system_info(host: str) -> str:
    """OS, noyau, uptime, CPU, mémoire, utilisateur courant."""
    r = rt()
    h = r.host(host)
    r.require(h, "read")
    if h.is_posix_shell:
        body = (
            'echo "hostname: $(hostname)"\n'
            'echo "user: $(id)"\n'
            '[ -r /etc/os-release ] && . /etc/os-release && echo "os: ${PRETTY_NAME:-?}"\n'
            'echo "kernel: $(uname -srm)"\n'
            'echo "uptime: $(uptime)"\n'
            'echo "cpus: $(nproc 2>/dev/null)"\n'
            'free -h 2>/dev/null\n'
            'command -v docker >/dev/null && echo "docker: $(docker --version 2>/dev/null)"\n'
            'command -v python3 >/dev/null && echo "python: $(python3 --version 2>&1)"\n'
            'command -v node >/dev/null && echo "node: $(node --version 2>&1)"\n'
            'command -v git >/dev/null && echo "git: $(git --version 2>&1)"\n'
            'exit 0\n'
        )
    else:
        body = r"""
Write-Output ('hostname: ' + [Environment]::MachineName)
Write-Output ('user: ' + [Environment]::UserDomainName + '\' + [Environment]::UserName)
Write-Output ('powershell: ' + $PSVersionTable.PSVersion)
try {
  $os = Get-CimInstance Win32_OperatingSystem
  Write-Output ('os: ' + $os.Caption + ' ' + $os.Version)
  Write-Output ('boot: ' + $os.LastBootUpTime)
  Write-Output ('mémoire: {0:N1} Go libres / {1:N1} Go' -f ($os.FreePhysicalMemory / 1MB), ($os.TotalVisibleMemorySize / 1MB))
} catch { Write-Output ('os: ' + [Environment]::OSVersion.VersionString) }
Write-Output ('cpus: ' + [Environment]::ProcessorCount)
foreach ($t in @('git', 'python', 'node', 'docker', 'dotnet')) {
  $c = Get-Command $t -ErrorAction SilentlyContinue
  if ($c) { Write-Output ($t + ': ' + $c.Source) }
}
"""
    res = await r.run(h, body)
    return r.format(res, f"system_info {host}")


@tool("read")
async def disk_usage(host: str, path: str | None = None) -> str:
    """Espace disque des volumes ; avec `path` (dans un allowed_path), taille de ce dossier."""
    r = rt()
    h = r.host(host)
    r.require(h, "read")
    if path:
        p = r.path(h, path, "list")
        if h.is_posix_shell:
            body = guard(h, p, "list") + 'du -sh -- "$P" 2>&1\n'
        else:
            body = guard(h, p, "list") + (
                "$s = (Get-ChildItem -LiteralPath $P -Recurse -Force -File -ErrorAction SilentlyContinue "
                "| Measure-Object Length -Sum).Sum\n"
                "Write-Output ('{0:N1} Mo  {1}' -f ($s / 1MB), $P)\n"
            )
    elif h.is_posix_shell:
        body = "df -hP -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null || df -hP\n"
    else:
        body = ("Get-PSDrive -PSProvider FileSystem | Select-Object Name, Root, "
                "@{n='UsedGB';e={[math]::Round($_.Used/1GB,1)}}, @{n='FreeGB';e={[math]::Round($_.Free/1GB,1)}} "
                "| Format-Table -AutoSize | Out-String -Width 200\n")
    res = await r.run(h, body, timeout=120)
    return r.format(res, f"disk_usage {host}")


@tool("read")
async def get_processes(host: str, sort_by: str = "cpu", limit: int = 25) -> str:
    """Processus les plus gourmands (sort_by = cpu | mem)."""
    r = rt()
    h = r.host(host)
    r.require(h, "read")
    n = clamp(limit, 1, 200)
    mem = sort_by == "mem"
    if h.is_posix_shell:
        key = "-%mem" if mem else "-%cpu"
        body = f"ps -eo pid,user,%cpu,%mem,etime,comm --sort={key} | head -n {n + 1}\n"
    else:
        key = "WorkingSet64" if mem else "CPU"
        body = (f"Get-Process | Sort-Object {key} -Descending | Select-Object -First {n} Id, ProcessName, "
                "@{n='CPU(s)';e={[math]::Round($_.CPU,1)}}, @{n='WS(Mo)';e={[math]::Round($_.WorkingSet64/1MB,1)}} "
                "| Format-Table -AutoSize | Out-String -Width 200\n")
    res = await r.run(h, body)
    return r.format(res, f"get_processes {host}")


@tool("read")
async def get_services(host: str, name_filter: str | None = None) -> str:
    """Services en cours d'exécution (filtre optionnel sur le nom, texte simple)."""
    r = rt()
    h = r.host(host)
    r.require(h, "read")
    if h.is_posix_shell:
        filt = f" | grep -iF -- {sh_quote(name_filter)}" if name_filter else ""
        body = ("systemctl list-units --type=service --state=running --no-pager --plain --no-legend 2>&1"
                f"{filt} | head -n 300\n")
    else:
        filt = f" | Where-Object {{ $_.Name -like ('*' + {ps_quote(name_filter)} + '*') }}" if name_filter else ""
        body = (f"Get-Service | Where-Object {{ $_.Status -eq 'Running' }}{filt} | Select-Object -First 300 Name, "
                "Status, DisplayName | Format-Table -AutoSize | Out-String -Width 250\n")
    res = await r.run(h, body)
    return r.format(res, f"get_services {host}")
