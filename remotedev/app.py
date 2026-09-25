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


def build_server(config: Config | None = None):
    config = config or load_config()
    errors = validate_startup(config)
    if errors:
        raise SystemExit("configuration refusée :\n  - " + "\n  - ".join(errors))
    set_runtime(Runtime(config))
    server = _Server("RemoteDev", instructions=INSTRUCTIONS)
    enabled = config.mode_levels
    for spec in REGISTRY:
        if spec.level not in enabled:
            continue  # en mode SAFE, les outils DEV ne sont même pas visibles
        # Noms « wire » (camelCase) : acceptés par mcp 1.x et 2.x.
        ann = ToolAnnotations.model_validate({
            "readOnlyHint": spec.read_only,
            "destructiveHint": spec.destructive,
            "idempotentHint": spec.read_only,
            "openWorldHint": False,
        })
        server.tool(name=spec.func.__name__, description=spec.description, annotations=ann)(spec.func)
    return server


def main() -> None:
    try:
        server = build_server()
    except (FileNotFoundError, ValueError) as exc:
        raise SystemExit(f"[remotedev] configuration invalide : {exc}")
    print(f"[remotedev {__version__}] démarré (stdio)", file=sys.stderr)
    server.run()
