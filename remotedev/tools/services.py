"""Services système et journaux."""

from __future__ import annotations

import re

from ..runtime import rt, sh_quote, ps_quote, tool
from ..security.errors import SecurityDenied, ToolError
from ..security.validator import clamp, validate_service
from ._common import guard

_EVENTLOG_RE = re.compile(r"^[A-Za-z0-9 /_.-]{1,100}$")
_FORBIDDEN_EVENTLOGS = {"security"}


@tool("read")
async def service_status(host: str, service: str) -> str:
    """État d'un service (systemctl status / Get-Service). Sous Linux, les unités --user sont
    essayées si l'unité système n'existe pas."""
    r = rt()
    h = r.host(host)
    r.require(h, "read")
    validate_service(service)
    if h.is_posix_shell:
        s = sh_quote(service)
        body = (f"systemctl status --no-pager --lines=0 {s} 2>&1; rc=$?\n"
                f"if [ $rc -eq 4 ]; then echo '--- unité utilisateur ---'; systemctl --user status --no-pager --lines=0 {s} 2>&1; rc=$?; fi\n"
                "exit $rc\n")
    else:
        body = (f"Get-Service -Name {ps_quote(service)} | Select-Object Name, DisplayName, Status, StartType "
                "| Format-List | Out-String -Width 200\n")
    res = await r.run(h, body)
    # systemctl status : 3 = inactif, ce n'est pas une erreur de l'outil.
    return r.format(res, f"service_status {service}")


@tool("read")
async def service_logs(host: str, service: str, lines: int = 200) -> str:
    """Journaux d'un service : journalctl -u (Linux, nécessite le groupe systemd-journal ou adm)
    ou événements du journal Application émis par ce fournisseur (Windows)."""
    r = rt()
    h = r.host(host)
    r.require(h, "read")
    validate_service(service)
    n = clamp(lines, 1, 5000)
    if h.is_posix_shell:
        s = sh_quote(service)
        body = (f"out=$(journalctl -u {s} -n {n} --no-pager -o short-iso 2>&1)\n"
                'case "$out" in *"No entries"*|"") '
                f"out=$(journalctl --user-unit {s} -n {n} --no-pager -o short-iso 2>&1) ;; esac\n"
                'printf "%s\\n" "$out"\n')
    else:
        body = (f"Get-WinEvent -FilterHashtable @{{LogName='Application'; ProviderName={ps_quote(service)}}} "
                f"-MaxEvents {n} -ErrorAction SilentlyContinue | Sort-Object TimeCreated "
                "| Format-Table TimeCreated, Id, LevelDisplayName, Message -Wrap | Out-String -Width 300\n")
    res = await r.run(h, body)
    return r.format(res, f"service_logs {service}")


@tool("dev", read_only=False)
async def restart_dev_service(host: str, service: str) -> str:
    """Redémarre un service présent dans services.restartable (hosts.yaml). Linux : systemctl --user
    (restart_mode: user) ou sudo -n systemctl (restart_mode: sudo, règle sudoers dédiée requise)."""
    r = rt()
    h = r.host(host)
    r.require(h, "dev")
    validate_service(service)
    if service not in h.services.restartable:
        raise SecurityDenied(f"service hors liste blanche : {service}")
    if h.is_posix_shell:
        s = sh_quote(service)
        if h.services.restart_mode == "user":
            body = f"systemctl --user restart {s} 2>&1 && systemctl --user is-active {s} 2>&1\n"
        else:
            body = f"sudo -n systemctl restart {s} 2>&1 && systemctl is-active {s} 2>&1\n"
    else:
        body = (f"Restart-Service -Name {ps_quote(service)}\n"
                f"(Get-Service -Name {ps_quote(service)}).Status.ToString()\n")
    res = await r.run(h, body, timeout=120)
    return r.format(res, f"restart_dev_service {service}")


@tool("read")
async def read_logs(host: str, source: str, lines: int = 200) -> str:
    """Fin d'un journal. `source` : nom déclaré dans log_sources (hosts.yaml), chemin absolu d'un
    fichier dans un allowed_path, 'journal' (journal système Linux) ou 'eventlog:<Nom>' (Windows,
    ex. eventlog:Application)."""
    r = rt()
    h = r.host(host)
    r.require(h, "read")
    n = clamp(lines, 1, 5000)
    if source in h.log_sources:
        # Chemin fixé par la configuration : peut être hors des allowed_paths (ex. /var/log/app).
        path = h.log_sources[source]
        body = (f"tail -n {n} -- {sh_quote(path)} 2>&1\n" if h.is_posix_shell
                else f"Get-Content -LiteralPath {ps_quote(path)} -Tail {n}\n")
    elif source == "journal":
        if not h.is_posix_shell:
            raise ToolError("'journal' n'existe que sous Linux")
        body = f"journalctl -n {n} --no-pager -o short-iso 2>&1\n"
    elif source.lower().startswith("eventlog:"):
        if h.is_posix_shell:
            raise ToolError("eventlog: n'existe que sous Windows")
        log = source.split(":", 1)[1]
        if not _EVENTLOG_RE.match(log) or log.lower() in _FORBIDDEN_EVENTLOGS:
            raise SecurityDenied(f"journal d'événements refusé : {log!r}")
        body = (f"Get-WinEvent -LogName {ps_quote(log)} -MaxEvents {n} | Sort-Object TimeCreated "
                "| Format-Table TimeCreated, Id, LevelDisplayName, ProviderName, Message -Wrap | Out-String -Width 300\n")
    else:
        p = r.path(h, source, "read")
        body = guard(h, p, "read") + (
            f'tail -n {n} -- "$P" 2>&1\n' if h.is_posix_shell else f"Get-Content -LiteralPath $P -Tail {n}\n"
        )
    res = await r.run(h, body)
    return r.format(res, f"read_logs {source}")
