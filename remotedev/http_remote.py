"""Mode HTTP à la demande, pour les clients qui n'acceptent que des serveurs distants
(appli ChatGPT, claude.ai) via un Cloudflare Quick Tunnel.

Principe :
- écoute uniquement sur 127.0.0.1 ; seul le tunnel sort vers Internet ;
- l'URL contient un secret de 256 bits régénéré à chaque lancement
  (https://xxx.trycloudflare.com/<secret>/mcp) : tout autre chemin répond 404 ;
- mode SAFE (lecture seule) forcé, sauf --allow-dev ;
- arrêt automatique après --minutes ;
- réponses JSON sans SSE : les Quick Tunnels ne transmettent pas les flux SSE.

Ce n'est pas de l'OAuth : quiconque obtient l'URL complète a accès aux outils tant que
le serveur tourne. Le secret se révoque en relançant le serveur.
"""

from __future__ import annotations

import asyncio
import re
import secrets
import shutil
import sys
import time
from typing import Any

from . import state
from .config import Config, load_config
from .runtime import rt

_TUNNEL_URL = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")


class SecretPathGate:
    """Middleware ASGI : n'accepte que /<secret>/..., et retire le préfixe."""

    def __init__(self, app: Any, token: str):
        self.app = app
        self.prefix = "/" + token

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)
        path: str = scope.get("path", "")
        head, sep, rest = path[1:].partition("/")
        if not sep or not secrets.compare_digest(("/" + head).encode(), self.prefix.encode()):
            await send({"type": "http.response.start", "status": 404,
                        "headers": [(b"content-type", b"text/plain")]})
            await send({"type": "http.response.body", "body": b"not found"})
            return
        new_path = "/" + rest
        scope = dict(scope, path=new_path, raw_path=new_path.encode(), root_path="")
        return await self.app(scope, receive, send)


def build_http_app(config: Config, token: str):
    """Application ASGI (serveur MCP streamable HTTP, JSON, sans état) derrière le secret."""
    from mcp.server.transport_security import TransportSecuritySettings

    from .app import build_server

    # Protection DNS rebinding désactivée : le SDK ne gère pas *.trycloudflare.com, et
    # une page piégée ne peut de toute façon pas deviner le secret du chemin.
    security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
    http_opts = {"json_response": True, "stateless_http": True, "transport_security": security}
    try:  # mcp >= 2 : options passées à streamable_http_app
        server = build_server(config)
        app = server.streamable_http_app(**http_opts)
    except TypeError:  # mcp 1.x : options passées au constructeur
        server = build_server(config, server_kwargs=http_opts)
        app = server.streamable_http_app()
    return SecretPathGate(app, token)


async def _start_tunnel(port: int) -> tuple[asyncio.subprocess.Process, str]:
    exe = shutil.which("cloudflared")
    if not exe:
        raise SystemExit("cloudflared introuvable (winget install Cloudflare.cloudflared)")
    proc = await asyncio.create_subprocess_exec(
        exe, "tunnel", "--no-autoupdate", "--url", f"http://127.0.0.1:{port}",
        stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
    )
    assert proc.stderr is not None

    async def find_url() -> str:
        while True:
            line = (await proc.stderr.readline()).decode("utf-8", "replace")
            if not line:
                raise SystemExit("cloudflared s'est arrêté avant de fournir une URL")
            found = _TUNNEL_URL.search(line)
            if found:
                return found.group(0)

    try:
        url = await asyncio.wait_for(find_url(), timeout=60)
    except asyncio.TimeoutError:
        proc.kill()
        raise SystemExit("cloudflared n'a pas fourni d'URL en 60 s")

    async def drain() -> None:  # évite que cloudflared bloque sur un tube plein
        while await proc.stderr.readline():
            pass

    asyncio.get_running_loop().create_task(drain())
    return proc, url


async def serve(port: int = 8765, tunnel: bool = True, minutes: int = 60, allow_dev: bool = False) -> None:
    import uvicorn

    config = load_config()
    if not allow_dev:
        config.policies.mode = "safe"
    token = secrets.token_urlsafe(32)
    app = build_http_app(config, token)
    rt().transport = "http"
    # access_log désactivé : il écrirait le secret du chemin dans la console.
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning",
                                           access_log=False, lifespan="on"))
    serve_task = asyncio.create_task(server.serve())
    while not server.started:
        if serve_task.done():
            await serve_task
            return
        await asyncio.sleep(0.05)

    proc = None
    base = f"http://127.0.0.1:{port}"
    started = time.time()
    expires = started + minutes * 60
    info = {"transport": "http", "mode": config.policies.mode, "port": port, "tunnel": tunnel,
            "started_at": started, "expires_at": expires}
    reason = "arrêt demandé"
    try:
        state.write({**info, "status": "démarrage du tunnel" if tunnel else "en cours"})
        if tunnel:
            proc, base = await _start_tunnel(port)
        url = f"{base}/{token}/mcp"
        state.write({**info, "status": "en cours", "url": url})
        print(
            "\n=== RemoteDev HTTP ===\n"
            f"mode        : {config.policies.mode.upper()}\n"
            f"arrêt auto  : dans {minutes} min (Ctrl+C, `remotedev stop` ou l'interface pour arrêter avant)\n"
            f"URL MCP     : {url}\n"
            "À coller dans ChatGPT > Paramètres > Applications > Créer, authentification : aucune.\n"
            "Cette URL EST le mot de passe : ne la partagez pas. Elle meurt à l'arrêt du serveur.\n",
            file=sys.stderr, flush=True,
        )
        while True:
            if serve_task.done():
                reason = "serveur arrêté"
                break
            if state.stop_requested():
                break
            if time.time() >= expires:
                reason = "durée écoulée"
                break
            if proc is not None and proc.returncode is not None:
                reason = "tunnel cloudflared arrêté"
                break
            await asyncio.sleep(1)
        print(f"[remotedev] {reason} : arrêt.", file=sys.stderr, flush=True)
    finally:
        server.should_exit = True
        if proc and proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=10)
            except asyncio.TimeoutError:
                proc.kill()
        await serve_task
        state.remove()
