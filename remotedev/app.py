"""Construction du serveur MCP."""

from __future__ import annotations

import sys
from pathlib import Path

from mcp.types import ToolAnnotations

try:  # mcp >= 2
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server  # type: ignore[no-redef]

from . import __version__
from . import tools as _tools  # noqa: F401  (enregistrement des outils)
from .config import Config, load_config
from .runtime import REGISTRY, Runtime, set_runtime
from .security.path_filter import _glob_match, _within, denied_patterns

INSTRUCTIONS = """\
RemoteDev donne un accès contrôlé à des projets sur des machines distantes.
- Commencer par host_list pour connaître les machines, projets et permissions.
- Tous les chemins sont absolus et doivent être dans les allowed_paths de la machine.
- Les fichiers secrets (.env, clés...) sont refusés : ne pas chercher à les contourner.
- Boucle de travail : git_status -> lecture ciblée -> run_tests -> patch_file -> run_tests -> git_diff.
- Préférer patch_file (remplacement exact et unique) à write_file pour modifier un fichier existant.
- Pour vérifier une app web déployée : browser_open puis browser_snapshot / browser_click / browser_fill
  (navigateur local, limité aux machines configurées, à localhost et à browser.allowed_origins).
- Aucun outil ne commit, ne push, ni ne lance de commande arbitraire : c'est volontaire.
"""


def validate_startup(config: Config) -> list[str]:
    """Erreurs bloquantes de configuration (retourne la liste, vide si OK)."""
    errors: list[str] = []
    for name, h in config.hosts.items():
        for root in h.allowed_paths:
            for pat in denied_patterns(h, config.policies):
                sep = "\\" if h.is_windows else "/"
                if _glob_match(root, pat, h.is_windows) or _glob_match(root, pat.rstrip(sep) + sep + "*", h.is_windows):
                    errors.append(f"{name}: allowed_path {root} est dans un chemin protégé ({pat})")
        for pname, proj in h.projects.items():
            if not any(_within(proj.path, r, h.is_windows) for r in h.allowed_paths):
                errors.append(f"{name}: projet {pname} ({proj.path}) hors des allowed_paths")
        if h.backend == "winrm" and sys.platform != "win32":
            print(f"[remotedev] ATTENTION : {name} utilise WinRM depuis un système non Windows ; pwsh sous Linux "
                  "ne sait pas s'y connecter sans module supplémentaire. Utiliser backend: ssh (PowerShell 7 over SSH).",
                  file=sys.stderr)
        if "admin" in h.permissions:
            print(f"[remotedev] ATTENTION : {name} a la permission admin (aucun outil admin n'est exposé)", file=sys.stderr)
    audit = Path(config.policies.audit_log)
    try:
        audit.parent.mkdir(parents=True, exist_ok=True)
        with audit.open("a", encoding="utf-8"):
            pass
    except OSError as exc:
        errors.append(f"journal d'audit non inscriptible ({audit}) : {exc}")
    return errors


def build_server(config: Config | None = None, server_kwargs: dict | None = None):
    config = config or load_config()
    errors = validate_startup(config)
    if errors:
        raise SystemExit("configuration refusée :\n  - " + "\n  - ".join(errors))
    set_runtime(Runtime(config))
    server = _Server("RemoteDev", instructions=INSTRUCTIONS, **(server_kwargs or {}))
    enabled = config.mode_levels
    for spec in REGISTRY:
        if spec.level not in enabled:
            continue  # en mode SAFE, les outils DEV ne sont même pas visibles
        if spec.func.__name__.startswith("browser_") and not config.policies.browser.enabled:
            continue
        # Noms « wire » (camelCase) : acceptés par mcp 1.x et 2.x.
        ann = ToolAnnotations.model_validate({
            "readOnlyHint": spec.read_only,
            "destructiveHint": spec.destructive,
            "idempotentHint": spec.read_only,
            "openWorldHint": spec.func.__name__.startswith("browser_"),
        })
        server.tool(name=spec.func.__name__, description=spec.description, annotations=ann)(spec.func)
    return server


def _has_display() -> bool:
    """Affichage graphique disponible ? (faux en SSH sur un mini PC sans écran)"""
    import os

    if sys.platform != "win32" and not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return False
    try:
        import tkinter  # noqa: F401
    except ImportError:
        return False
    return True


def _print_status() -> None:
    from . import state

    insts = state.instances()
    if not insts:
        print("RemoteDev : aucune instance en cours.")
        return
    for inst in insts:
        print("● " + state.describe(inst) + f" — {inst.get('status', '')}")
        if inst.get("url"):
            print(f"    URL : {inst['url']}")


def _stop(target: str) -> None:
    from . import state

    insts = [i for i in state.instances() if i.get("transport") == "http"]
    if target != "all":
        insts = [i for i in insts if str(i["pid"]) == target]
    if not insts:
        print("Aucune instance HTTP à arrêter. (Une instance stdio s'arrête en fermant Claude Desktop.)")
        return
    for inst in insts:
        state.request_stop(int(inst["pid"]))
        print(f"arrêt demandé : pid {inst['pid']}")


def _check() -> None:
    import asyncio

    from .health import check_all

    for h in asyncio.run(check_all(load_config())):
        print(f"{'OK ' if h.ok else 'KO '} {h.name:<20} {h.seconds:5.1f}s  {h.detail}")


def main(argv: list[str] | None = None) -> None:
    import argparse

    parser = argparse.ArgumentParser(description="MCP RemoteDev (sans option : serveur stdio pour Claude Desktop/Code)")
    parser.add_argument("--http", action="store_true",
                        help="mode HTTP à la demande (ChatGPT, claude.ai) au lieu de stdio")
    parser.add_argument("--no-tunnel", action="store_true", help="ne pas lancer cloudflared (HTTP local seul)")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--minutes", type=int, default=60, help="arrêt automatique (mode HTTP)")
    parser.add_argument("--allow-dev", action="store_true",
                        help="mode HTTP : garder le mode de policies.yaml au lieu de forcer SAFE")
    parser.add_argument("--status", action="store_true", help="afficher les instances en cours")
    parser.add_argument("--stop", nargs="?", const="all", metavar="PID", help="arrêter l'instance HTTP (toutes par défaut)")
    parser.add_argument("--check", action="store_true", help="tester la connexion à chaque machine")
    parser.add_argument("--ui", action="store_true",
                        help="ouvrir la mini-interface (mode texte automatique sans écran)")
    parser.add_argument("--tui", action="store_true", help="tableau de bord en mode texte (SSH, mini PC sans écran)")
    args = parser.parse_args(argv)
    try:
        if args.status:
            return _print_status()
        if args.stop:
            return _stop(args.stop)
        if args.check:
            return _check()
        if args.tui or (args.ui and not _has_display()):
            from .tui import run_tui

            return run_tui()
        if args.ui:
            from .ui import run_ui

            return run_ui()
        if args.http:
            import asyncio

            from . import state
            from .http_remote import serve

            try:
                asyncio.run(serve(args.port, not args.no_tunnel, max(1, args.minutes), args.allow_dev))
            except KeyboardInterrupt:
                state.remove()
            return
        server = build_server()
    except (FileNotFoundError, ValueError) as exc:
        raise SystemExit(f"[remotedev] configuration invalide : {exc}")

    import atexit
    import time

    from . import state

    state.write({"transport": "stdio", "mode": server_mode(), "status": "en cours (lancé par le client MCP)",
                 "started_at": time.time()})
    atexit.register(state.remove)
    print(f"[remotedev {__version__}] démarré (stdio)", file=sys.stderr)
    server.run()


def server_mode() -> str:
    from .runtime import rt

    return rt().policies.mode
