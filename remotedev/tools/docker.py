"""Outils Docker.

Rappel brutal : un utilisateur membre du groupe `docker` est root sur la machine
(`docker run -v /:/host ...`). Ces outils n'exposent pas `docker run`, et
docker_compose_up refuse les configurations qui donnent accès à l'hôte, mais le code
lancé par run_tests peut appeler docker directement. Activer docker sur un hôte,
c'est accepter ce risque.
"""

from __future__ import annotations

import json

from ..config import HostConfig
from ..runtime import rt, tool
from ..security.errors import SecurityDenied, ToolError
from ..security.path_filter import _within
from ..security.validator import clamp, validate_container
from ._common import guard, run_argv


def _docker_host(host: str, level: str) -> HostConfig:
    r = rt()
    h = r.host(host)
    r.require(h, level)
    if not h.docker.enabled:
        raise SecurityDenied(f"docker désactivé pour {host} (docker.enabled: true dans hosts.yaml)")
    return h


def _check_container(h: HostConfig, container: str, restart: bool) -> str:
    validate_container(container)
    allowed = h.docker.allowed_containers
    if restart and not allowed:
        raise SecurityDenied("aucun conteneur autorisé au redémarrage (docker.allowed_containers)")
    if allowed and container not in allowed:
        raise SecurityDenied(f"conteneur hors liste blanche : {container}")
    return container


async def _docker(h: HostConfig, argv: list[str], title: str, project_path: str | None = None,
                  timeout: int | None = None) -> str:
    r = rt()
    body = guard(h, project_path, "list") + run_argv(h, argv) if project_path else run_argv(h, argv, cwd_var=None)
    res = await r.run(h, body, timeout=timeout)
    return r.format(res, title)


def compose_violations(cfg: dict, h: HostConfig) -> list[str]:
    """Éléments d'une config compose (sortie de `docker compose config --format json`)
    qui donnent accès à l'hôte."""
    problems: list[str] = []
    for name, svc in (cfg.get("services") or {}).items():
        if svc.get("privileged"):
            problems.append(f"{name}: privileged")
        for key in ("pid", "ipc", "uts", "userns_mode", "network_mode"):
            if str(svc.get(key, "")) == "host":
                problems.append(f"{name}: {key}=host")
        if svc.get("cap_add"):
            problems.append(f"{name}: cap_add={svc['cap_add']}")
        if svc.get("devices"):
            problems.append(f"{name}: devices")
        for opt in svc.get("security_opt") or []:
            if "unconfined" in str(opt) or "disable" in str(opt):
                problems.append(f"{name}: security_opt={opt}")
        for vol in svc.get("volumes") or []:
            if not isinstance(vol, dict) or vol.get("type") != "bind":
                continue
            src = str(vol.get("source", ""))
            if "docker.sock" in src:
                problems.append(f"{name}: montage du socket docker")
            elif not any(_within(h.normpath(src), root, h.is_windows) for root in h.allowed_paths):
                problems.append(f"{name}: bind mount hors allowed_paths ({src})")
    return problems


@tool("read")
async def docker_ps(host: str, all: bool = False) -> str:
    """Conteneurs (all=true pour inclure les arrêtés)."""
    h = _docker_host(host, "read")
    argv = ["docker", "ps", "--format", "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"]
    if all:
        argv.insert(2, "-a")
    return await _docker(h, argv, f"docker ps {host}")


@tool("read")
async def docker_images(host: str) -> str:
    """Images Docker présentes."""
    h = _docker_host(host, "read")
    return await _docker(h, ["docker", "images", "--format", "table {{.Repository}}:{{.Tag}}\t{{.ID}}\t{{.Size}}\t{{.CreatedSince}}"],
                         f"docker images {host}")


@tool("read")
async def docker_logs(host: str, container: str, lines: int = 200, since: str | None = None) -> str:
    """Dernières lignes de logs d'un conteneur (since : ex. '10m', '2h')."""
    h = _docker_host(host, "read")
    _check_container(h, container, restart=False)
    argv = ["docker", "logs", "--tail", str(clamp(lines, 1, 5000)), "--timestamps"]
    if since:
        if not since[:-1].isdigit() or since[-1] not in "smhd":
            raise ToolError("since invalide (ex. 30s, 10m, 2h, 1d)")
        argv += ["--since", since]
    return await _docker(h, argv + [container], f"docker logs {container}")


@tool("read")
async def docker_compose_status(host: str, project: str) -> str:
    """docker compose ps dans le dossier du projet."""
    h = _docker_host(host, "read")
    p = rt().project_path(h, project)
    return await _docker(h, ["docker", "compose", "ps", "-a"], f"docker compose ps ({p})", project_path=p)


@tool("dev", read_only=False)
async def docker_compose_up(host: str, project: str, build: bool = False) -> str:
    """docker compose up -d (build=true pour reconstruire). Refusé si la configuration donne accès
    à l'hôte (privileged, network/pid host, cap_add, devices, bind mounts hors projet, socket docker)."""
    r = rt()
    h = _docker_host(host, "dev")
    p = r.project_path(h, project)
    if not h.docker.allow_unsafe_compose:
        res = await r.run(h, guard(h, p, "list") + run_argv(h, ["docker", "compose", "config", "--format", "json"]))
        if res.exit_code != 0:
            raise ToolError(f"docker compose config a échoué : {(res.stderr or res.stdout).strip()[:1500]}")
        try:
            cfg = json.loads(res.stdout[res.stdout.index("{"):])
        except ValueError as exc:
            raise ToolError(f"sortie de docker compose config illisible : {exc}")
        problems = compose_violations(cfg, h)
        if problems:
            raise SecurityDenied("configuration compose dangereuse : " + "; ".join(problems))
    argv = ["docker", "compose", "up", "-d", "--remove-orphans"] + (["--build"] if build else [])
    return await _docker(h, argv, f"docker compose up ({p})", project_path=p,
                         timeout=r.policies.timeouts.docker_compose)


@tool("dev", read_only=False, destructive=True)
async def docker_compose_down(host: str, project: str) -> str:
    """docker compose down (les volumes sont conservés : jamais de -v)."""
    r = rt()
    h = _docker_host(host, "dev")
    p = r.project_path(h, project)
    return await _docker(h, ["docker", "compose", "down", "--remove-orphans"], f"docker compose down ({p})",
                         project_path=p, timeout=r.policies.timeouts.docker_compose)


@tool("dev", read_only=False)
async def docker_restart(host: str, container: str) -> str:
    """Redémarre un conteneur de la liste blanche docker.allowed_containers."""
    h = _docker_host(host, "dev")
    _check_container(h, container, restart=True)
    return await _docker(h, ["docker", "restart", container], f"docker restart {container}")
