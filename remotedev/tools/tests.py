"""run_tests / run_build : détection du type de projet et commande adaptée.

Attention : lancer les tests ou le build exécute du code du projet, donc du code que
le modèle a pu écrire. En mode DEV, write_file + run_tests = exécution de code
arbitraire avec les droits de l'utilisateur distant. La frontière de sécurité est
cet utilisateur, pas ce module.
"""

from __future__ import annotations

import re

from ..runtime import rt, tool
from ..security.command_filter import check_command
from ..security.errors import ToolError
from ._common import guard, run_argv, run_trusted

_TARGET_RE = re.compile(r"^[A-Za-z0-9_./:\[\]\\=-]{1,300}$")

_MARKERS = [
    "pytest.ini", "pyproject.toml", "setup.cfg", "tox.ini", "setup.py", "requirements.txt", "tests",
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    "Cargo.toml", "go.mod", "Makefile",
    "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml",
    ".venv/bin/python", "venv/bin/python", ".venv/Scripts/python.exe", "venv/Scripts/python.exe",
]


async def detect(host: str, project: str) -> tuple[str, set[str]]:
    r = rt()
    h = r.host(host)
    p = r.project_path(h, project)
    if h.is_posix_shell:
        names = " ".join(f"'{m}'" for m in _MARKERS)
        body = guard(h, p, "list") + (
            'cd "$P" || exit 2\n'
            f"for f in {names}; do [ -e \"$f\" ] && echo \"$f\"; done\n"
            "ls *.sln *.csproj 2>/dev/null | head -n 1 | sed 's/.*/dotnet/'\n"
            "[ -f package.json ] && grep -q '\"test\"[[:space:]]*:' package.json && echo pkg:test\n"
            "[ -f package.json ] && grep -q '\"build\"[[:space:]]*:' package.json && echo pkg:build\n"
            "[ -f pyproject.toml ] && grep -q '^\\[tool.pytest' pyproject.toml && echo pyproject:pytest\n"
            "[ -f pyproject.toml ] && grep -q '^\\[build-system\\]' pyproject.toml && echo pyproject:build\n"
            "[ -f Makefile ] && grep -q '^test:' Makefile && echo make:test\n"
            "[ -f Makefile ] && grep -q '^build:' Makefile && echo make:build\n"
            "exit 0\n"
        )
    else:
        arr = ", ".join(f"'{m}'" for m in _MARKERS)
        body = guard(h, p, "list") + f"""
Set-Location -LiteralPath $P
foreach ($f in @({arr})) {{ if (Test-Path -LiteralPath $f) {{ Write-Output $f }} }}
if (Get-ChildItem -Filter *.sln -ErrorAction SilentlyContinue) {{ Write-Output 'dotnet' }}
elseif (Get-ChildItem -Filter *.csproj -ErrorAction SilentlyContinue) {{ Write-Output 'dotnet' }}
if (Test-Path package.json) {{
  $pj = Get-Content -Raw package.json
  if ($pj -match '"test"\\s*:') {{ Write-Output 'pkg:test' }}
  if ($pj -match '"build"\\s*:') {{ Write-Output 'pkg:build' }}
}}
if (Test-Path pyproject.toml) {{
  $pp = Get-Content -Raw pyproject.toml
  if ($pp -match '(?m)^\\[tool\\.pytest') {{ Write-Output 'pyproject:pytest' }}
  if ($pp -match '(?m)^\\[build-system\\]') {{ Write-Output 'pyproject:build' }}
}}
if (Test-Path Makefile) {{
  $mk = Get-Content -Raw Makefile
  if ($mk -match '(?m)^test:') {{ Write-Output 'make:test' }}
  if ($mk -match '(?m)^build:') {{ Write-Output 'make:build' }}
}}
"""
    res = await r.run(h, body)
    if res.exit_code != 0:
        raise ToolError(f"détection impossible : {res.stderr.strip()[:500]}")
    return p, {ln.strip() for ln in res.stdout.splitlines() if ln.strip()}


def _python(host_windows: bool, m: set[str]) -> str:
    for cand in (".venv/bin/python", "venv/bin/python"):
        if cand in m:
            return "./" + cand
    for cand in (".venv/Scripts/python.exe", "venv/Scripts/python.exe"):
        if cand in m:
            return ".\\" + cand.replace("/", "\\")
    return "python" if host_windows else "python3"


def _node_runner(m: set[str], windows: bool) -> str:
    runner = "pnpm" if "pnpm-lock.yaml" in m else "yarn" if "yarn.lock" in m else "npm"
    # Sous Windows, viser le .cmd : le .ps1 est bloqué par l'ExecutionPolicy de PowerShell 5.1.
    return runner + ".cmd" if windows else runner


def plan(kind: str, m: set[str], windows: bool, target: str | None) -> tuple[str, list[str]] | None:
    """Retourne (type détecté, argv) pour kind = test | build."""
    py = _python(windows, m)
    is_py = bool(m & {"pytest.ini", "pyproject:pytest", "setup.cfg", "tox.ini", "setup.py", "requirements.txt"}) \
        or ("tests" in m and "package.json" not in m)
    extra = [target] if target else []
    if kind == "test":
        if "pkg:test" in m:
            runner = _node_runner(m, windows)
            return "node", [runner, "test"] + (["--", target] if target else [])
        if is_py or "pyproject.toml" in m:
            return "python", [py, "-m", "pytest", "-q", "-p", "no:cacheprovider"] + extra
        if "Cargo.toml" in m:
            return "rust", ["cargo", "test"] + extra
        if "go.mod" in m:
            return "go", ["go", "test", target or "./..."]
        if "dotnet" in m:
            return "dotnet", ["dotnet", "test"] + (["--filter", target] if target else [])
        if "make:test" in m:
            return "make", ["make", "test"]
        return None
    if "pkg:build" in m:
        return "node", [_node_runner(m, windows), "run", "build"]
    if "pyproject:build" in m:
        return "python", [py, "-m", "build"]
    if "Cargo.toml" in m:
        return "rust", ["cargo", "build"]
    if "go.mod" in m:
        return "go", ["go", "build", "./..."]
    if "dotnet" in m:
        return "dotnet", ["dotnet", "build"]
    if "make:build" in m:
        return "make", ["make", "build"]
    if m & {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
        return "docker", ["docker", "compose", "build"]
    return None


async def _run(kind: str, host: str, project: str, target: str | None) -> str:
    r = rt()
    h = r.host(host)
    r.require(h, "dev")
    if target is not None and not _TARGET_RE.match(target):
        raise ToolError("target invalide (chemin de test, node id pytest ou filtre simple attendu)")
    p = r.project_path(h, project)
    timeout = r.policies.timeouts.tests if kind == "test" else r.policies.timeouts.build
    proj = r.project_config(h, p)
    override = (proj.test if kind == "test" else proj.build) if proj else None
    if override:
        check_command(override, r.policies.blocked_command_patterns)
        body = guard(h, p, "list") + run_trusted(h, override)
        label = f"commande configurée : {override}"
    else:
        p, markers = await detect(host, project)
        chosen = plan(kind, markers, h.is_windows, target)
        if chosen is None:
            raise ToolError(
                f"type de projet non détecté dans {p} (marqueurs : {sorted(markers) or 'aucun'}). "
                f"Définir projects.<nom>.{kind} dans hosts.yaml."
            )
        detected, argv = chosen
        if detected == "docker" and not h.docker.enabled:
            raise ToolError("projet docker compose mais docker désactivé pour cet hôte")
        body = guard(h, p, "list") + run_argv(h, argv)
        label = f"{detected} : {' '.join(argv)}"
    res = await r.run(h, body, timeout=timeout)
    return r.format(res, f"{'run_tests' if kind == 'test' else 'run_build'} [{label}]")


@tool("dev", read_only=False)
async def run_tests(host: str, project: str, target: str | None = None) -> str:
    """Lance les tests du projet (pytest, npm/pnpm/yarn test, cargo, go, dotnet, make test — détection
    automatique ou commande définie dans hosts.yaml). `target` : fichier ou test précis (ex.
    tests/test_api.py::test_login)."""
    return await _run("test", host, project, target)


@tool("dev", read_only=False)
async def run_build(host: str, project: str) -> str:
    """Lance le build (npm run build, python -m build, cargo/go/dotnet build, make build, docker compose build)."""
    return await _run("build", host, project, None)
