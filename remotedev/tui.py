"""Tableau de bord en mode texte (curses) : pour un mini PC sans écran, utilisé via SSH,
y compris depuis un téléphone (Termius, JuiceSSH...).

Mêmes informations et actions que la mini-interface graphique. La logique d'affichage
(`render`) est pure et testée ; `run_tui` ne fait que dessiner et lire le clavier.
"""

from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from . import state
from .ui import audit_tail, format_audit, http_log_tail, launch_http, mask_url, stop_http

KEYS = "[s] démarrer  [x] arrêter  [+/-] durée  [d] écriture DEV  [t] tunnel  [u] URL  [c] tester  [q] quitter"


@dataclass
class TuiState:
    minutes: int = 30
    allow_dev: bool = False
    tunnel: bool = True
    show_secret: bool = False
    confirm_dev: bool = False
    message: str = ""
    launching_since: float | None = None
    proc: Any = None
    last_error: str = ""
    health: dict[str, tuple[bool, str, float]] = field(default_factory=dict)
    checking: bool = False


def render(now: float, insts: list[dict[str, Any]], audit: list[dict[str, Any]], hosts: list[str],
           st: TuiState) -> list[tuple[str, str]]:
    """Lignes à afficher : (texte, style) avec style ∈ normal|title|ok|warn|bad|dim."""
    lines: list[tuple[str, str]] = [(f"RemoteDev — {time.strftime('%H:%M:%S', time.localtime(now))}", "title"), ("", "normal")]
    http = next((i for i in insts if i.get("transport") == "http"), None)
    stdio = [i for i in insts if i.get("transport") == "stdio"]
    if http:
        running = http.get("status") == "en cours"
        lines.append((f"HTTP  : ● {http.get('status', '?')} · {state.describe(http)}", "ok" if running else "warn"))
        url = http.get("url", "")
        if url:
            lines.append((f"URL   : {url if st.show_secret else mask_url(url)}", "normal"))
    elif st.launching_since:
        lines.append(("HTTP  : ● démarrage…", "warn"))
    elif st.last_error:
        lines.append(("HTTP  : ● échec du démarrage", "bad"))
        lines += [(f"        {ln}", "dim") for ln in st.last_error.splitlines()[-3:]]
    else:
        lines.append(("HTTP  : ○ arrêté", "dim"))
    lines.append(("stdio : " + (", ".join(f"actif pid {i['pid']}" for i in stdio) if stdio else "aucune instance"),
                  "normal"))
    lines.append(("", "normal"))
    dev = "OUI" if st.allow_dev else "non"
    lines.append((f"Prochain démarrage : {st.minutes} min · tunnel {'oui' if st.tunnel else 'non'} · écriture DEV {dev}",
                  "bad" if st.allow_dev else "normal"))
    lines.append((KEYS, "dim"))
    lines.append(("", "normal"))
    lines.append(("Machines" + ("  (test en cours…)" if st.checking else ""), "title"))
    for name in hosts:
        if name in st.health:
            ok, detail, secs = st.health[name]
            lines.append((f"  {name:<20} {'OK' if ok else 'KO':<3} {secs:5.1f}s  {detail}", "ok" if ok else "bad"))
        else:
            lines.append((f"  {name:<20} ?", "dim"))
    lines.append(("", "normal"))
    lines.append(("Dernières actions", "title"))
    for entry in audit:
        style = {"SUCCESS": "normal", "DENIED": "bad", "ERROR": "warn"}.get(entry.get("result", ""), "normal")
        lines.append(("  " + format_audit(entry), style))
    if not audit:
        lines.append(("  (aucune)", "dim"))
    if st.message:
        lines += [("", "normal"), (st.message, "warn")]
    return lines


def _host_names() -> list[str]:
    try:
        from .config import load_config

        return sorted(load_config().hosts)
    except Exception as exc:
        return [f"(configuration invalide : {exc})"]


def _audit_path():
    from pathlib import Path

    try:
        from .config import load_config

        return Path(load_config().policies.audit_log)
    except Exception:
        from .ui import BASE

        return BASE / "logs" / "audit.log"


def handle_key(key: str, st: TuiState, http_running: bool) -> bool:
    """Applique une touche. Retourne False pour quitter."""
    st.message = ""
    if st.confirm_dev:
        st.confirm_dev = False
        if key.lower() == "o":
            st.proc = launch_http(st.minutes, True, st.tunnel)
            st.launching_since, st.last_error = time.time(), ""
        else:
            st.message = "Démarrage annulé."
        return True
    if key == "q":
        return False
    if key == "+":
        st.minutes = min(240, st.minutes + 5)
    elif key == "-":
        st.minutes = max(5, st.minutes - 5)
    elif key == "d":
        st.allow_dev = not st.allow_dev
    elif key == "t":
        st.tunnel = not st.tunnel
    elif key == "u":
        st.show_secret = not st.show_secret
    elif key == "x":
        st.message = "Arrêt demandé." if stop_http() else "Aucune instance HTTP."
    elif key == "s":
        if http_running or st.launching_since:
            st.message = "Déjà lancé."
        elif st.allow_dev:
            st.confirm_dev = True
            st.message = "Écriture DEV via une URL publique : l'IA pourra exécuter du code. Confirmer ? [o/N]"
        else:
            st.proc = launch_http(st.minutes, False, st.tunnel)
            st.launching_since, st.last_error = time.time(), ""
    return True


def _check(st: TuiState) -> None:
    from .config import load_config
    from .health import check_all

    st.checking = True
    try:
        st.health = {h.name: (h.ok, h.detail, h.seconds) for h in asyncio.run(check_all(load_config()))}
    except Exception as exc:
        st.message = f"Test impossible : {exc}"
    finally:
        st.checking = False


def run_tui() -> None:
    import curses

    def main(scr) -> None:
        curses.curs_set(0)
        scr.timeout(1000)
        styles = {"normal": curses.A_NORMAL, "title": curses.A_BOLD, "dim": curses.A_DIM,
                  "ok": curses.A_NORMAL, "warn": curses.A_BOLD, "bad": curses.A_BOLD}
        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
            for n, color in ((1, curses.COLOR_GREEN), (2, curses.COLOR_YELLOW), (3, curses.COLOR_RED)):
                curses.init_pair(n, color, -1)
            styles.update(ok=curses.color_pair(1), warn=curses.color_pair(2) | curses.A_BOLD,
                          bad=curses.color_pair(3) | curses.A_BOLD)
        st = TuiState()
        hosts = _host_names()
        audit_path = _audit_path()
        while True:
            insts = state.instances()
            http = next((i for i in insts if i.get("transport") == "http"), None)
            if http:
                st.launching_since = None
            elif st.launching_since and (st.proc is None or st.proc.poll() is not None
                                         or time.time() - st.launching_since > 90):
                st.launching_since = None
                st.last_error = http_log_tail() or "échec : voir logs/http.log"
            scr.erase()
            height, width = scr.getmaxyx()
            for y, (text, style) in enumerate(render(time.time(), insts, audit_tail(audit_path), hosts, st)):
                if y >= height - 1:
                    break
                try:
                    scr.addnstr(y, 0, text, width - 1, styles.get(style, curses.A_NORMAL))
                except curses.error:
                    pass
            scr.refresh()
            ch = scr.getch()
            if ch == -1:
                continue
            key = chr(ch) if 0 <= ch < 256 else ""
            if key == "c" and not st.checking:
                threading.Thread(target=_check, args=(st,), daemon=True).start()
                continue
            if not handle_key(key, st, http is not None and http.get("status") == "en cours"):
                break

    curses.wrapper(main)
