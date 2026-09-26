"""install_dependencies : installe les dépendances d'un projet, uniquement dans le projet.

Jamais d'installation globale ni de sudo : npm/pnpm/yarn dans node_modules, pip dans le
venv du projet (créé en .venv s'il n'existe pas). Comme run_tests, ceci exécute du code
tiers (scripts postinstall, setup.py) avec les droits de l'utilisateur distant ;
ignore_scripts=true désactive les scripts npm/pnpm/yarn.
"""

from __future__ import annotations

from ..runtime import rt, tool
from ..security.errors import ToolError
from ._common import guard, run_argv
from .tests import _node_runner, _python, detect

KINDS = ("node", "python", "rust", "go", "dotnet")


def plan_install(m: set[str], windows: bool, kind: str | None = None,
                 ignore_scripts: bool = False) -> list[tuple[str, list[str]]]:
    """Étapes (type, argv) dans l'ordre. Liste vide si rien à installer."""
    steps: list[tuple[str, list[str]]] = []
    if "package.json" in m and kind in (None, "node"):
        runner = _node_runner(m, windows)
        base = runner.split(".")[0]
        if base == "pnpm":
            argv = [runner, "install", "--frozen-lockfile"]
        elif base == "yarn":
            argv = [runner, "install", "--frozen-lockfile"]
        elif "package-lock.json" in m:
            argv = [runner, "ci"]
        else:
            argv = [runner, "install"]
        if ignore_scripts:
            argv.append("--ignore-scripts")
        steps.append(("node", argv))
    installable = "pyproject:build" in m or "setup.py" in m
    if ("requirements.txt" in m or installable) and kind in (None, "python"):
        py = _python(windows, m)
        if not py.startswith((".", "/")):  # pas de venv dans le projet : on le crée
            steps.append(("python", [py, "-m", "venv", ".venv"]))
            py = ".\\.venv\\Scripts\\python.exe" if windows else "./.venv/bin/python"
        if "requirements.txt" in m:
            steps.append(("python", [py, "-m", "pip", "install", "--disable-pip-version-check", "-r", "requirements.txt"]))
        else:
            steps.append(("python", [py, "-m", "pip", "install", "--disable-pip-version-check", "-e", "."]))
    if "Cargo.toml" in m and kind in (None, "rust"):
        steps.append(("rust", ["cargo", "fetch"]))
    if "go.mod" in m and kind in (None, "go"):
        steps.append(("go", ["go", "mod", "download"]))
    if "dotnet" in m and kind in (None, "dotnet"):
        steps.append(("dotnet", ["dotnet", "restore"]))
    return steps


@tool("dev", read_only=False)
async def install_dependencies(host: str, project: str, kind: str | None = None,
                               ignore_scripts: bool = False) -> str:
    """Installe les dépendances DU PROJET (jamais globalement) : npm ci / pnpm / yarn,
    pip dans le venv du projet (.venv créé si absent), cargo fetch, go mod download,
    dotnet restore. kind = node | python | rust | go | dotnet pour n'en traiter qu'un.
    ignore_scripts=true : pas de scripts postinstall npm/pnpm/yarn."""
    r = rt()
    h = r.host(host)
    r.require(h, "dev")
    if kind is not None and kind not in KINDS:
        raise ToolError(f"kind doit être l'un de : {', '.join(KINDS)}")
    p, markers = await detect(host, project)
    steps = plan_install(markers, h.is_windows, kind, ignore_scripts)
    if not steps:
        raise ToolError(f"aucune dépendance à installer détectée dans {p} (marqueurs : {sorted(markers) or 'aucun'})")
    body = guard(h, p, "list") + "".join(run_argv(h, argv, check=True) for _, argv in steps)
    res = await r.run(h, body, timeout=r.policies.timeouts.install)
    label = " ; ".join(" ".join(argv) for _, argv in steps)
    return r.format(res, f"install_dependencies [{label}]")
