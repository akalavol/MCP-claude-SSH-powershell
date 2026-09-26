"""Navigateur piloté (Playwright, Chromium) : vérifier une application web déployée sur une cible.

Le navigateur tourne sur la machine du MCP, pas sur la cible. Toute requête (page,
redirection, script, image, fetch) vers une origine non autorisée est bloquée :
seules sont permises les machines de hosts.yaml, localhost et policies.browser.allowed_origins.
Sans cela, un modèle manipulé par le contenu d'une page pourrait faire sortir des
données ou atteindre d'autres machines du réseau local.

Dépendance optionnelle : pip install playwright && python -m playwright install chromium
"""

from __future__ import annotations

import asyncio
from collections import deque
from urllib.parse import urlsplit

from ..runtime import rt, tool
from ..security.errors import SecurityDenied, ToolError

try:  # mcp >= 2
    from mcp.server.mcpserver import Image
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import Image  # type: ignore[no-redef]

_LOCAL = {"localhost", "127.0.0.1", "::1"}


def _origin_key(url: str) -> tuple[str, str, int | None]:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    port = parts.port or {"http": 80, "https": 443}.get(parts.scheme)
    return parts.scheme.lower(), host, port


def url_allowed(url: str, machine_hosts: set[str], allowed_origins: list[str]) -> bool:
    """http(s) uniquement ; machine de hosts.yaml ou localhost (tout port), ou origine listée."""
    scheme, host, port = _origin_key(url)
    if scheme not in ("http", "https") or not host:
        return False
    if host in _LOCAL or host in machine_hosts or "*" in allowed_origins:
        return True
    for entry in allowed_origins:
        if "://" in entry:
            if _origin_key(entry) == (scheme, host, port):
                return True
        elif entry.lower() == host:  # nom d'hôte seul : tout schéma, tout port
            return True
    return False


class _Session:
    def __init__(self) -> None:
        self.lock = asyncio.Lock()
        self.loop: asyncio.AbstractEventLoop | None = None
        self.pw = self.browser = self.context = self.page = None
        self.console: deque[str] = deque(maxlen=300)
        self.blocked: deque[str] = deque(maxlen=50)

    def _allowed(self, url: str) -> bool:
        r = rt()
        machines = {h.host.lower() for h in r.config.hosts.values() if h.host}
        return url_allowed(url, machines, r.policies.browser.allowed_origins)

    async def _route(self, route) -> None:
        url = route.request.url
        if self._allowed(url):
            await route.continue_()
            return
        scheme, host, port = _origin_key(url)
        origin = f"{scheme}://{host}:{port}"
        if origin not in self.blocked:
            self.blocked.append(origin)
        await route.abort("blockedbyclient")

    def _watch(self, page) -> None:
        page.on("console", lambda m: self.console.append(f"[{m.type}] {m.text}"))
        page.on("pageerror", lambda e: self.console.append(f"[pageerror] {e}"))

    async def page_(self):
        loop = asyncio.get_running_loop()
        if self.loop is not loop:  # nouvelle boucle : l'ancienne session est inutilisable
            self.pw = self.browser = self.context = self.page = None
            self.loop = loop
        if self.page is not None and not self.page.is_closed():
            return self.page
        if self.context is None:
            try:
                from playwright.async_api import async_playwright
            except ImportError:
                raise ToolError("Playwright absent : pip install playwright puis python -m playwright install chromium")
            cfg = rt().policies.browser
            self.pw = await async_playwright().start()
            try:
                self.browser = await self.pw.chromium.launch(headless=cfg.headless)
            except Exception as exc:
                await self.pw.stop()
                self.pw = None
                raise ToolError(f"Chromium introuvable ({exc.__class__.__name__}) : python -m playwright install chromium")
            # service workers bloqués : sinon leurs requêtes échapperaient au filtrage.
            self.context = await self.browser.new_context(
                accept_downloads=False, service_workers="block", ignore_https_errors=False,
                viewport={"width": 1280, "height": 800},
            )
            self.context.set_default_timeout(cfg.timeout * 1000)
            await self.context.route("**/*", self._route)
            self.context.on("page", self._watch)
        self.page = await self.context.new_page()
        return self.page

    async def close(self) -> bool:
        was_open = self.pw is not None
        if self.pw is not None and self.loop is asyncio.get_running_loop():
            try:
                await self.browser.close()
            finally:
                await self.pw.stop()
        self.pw = self.browser = self.context = self.page = None
        self.console.clear()
        self.blocked.clear()
        return was_open


_S = _Session()


def _check(level: str) -> None:
    r = rt()
    if not r.policies.browser.enabled:
        raise SecurityDenied("navigateur désactivé (policies.yaml : browser.enabled)")
    if level not in r.config.mode_levels:
        raise SecurityDenied(f"niveau {level.upper()} désactivé (mode global {r.policies.mode.upper()})")


async def _state(page, snapshot: bool = True) -> str:
    try:
        await page.wait_for_load_state("domcontentloaded", timeout=5000)
    except Exception:
        pass
    parts = [f"URL : {page.url}", f"Titre : {await page.title()}"]
    if _S.blocked:
        parts.append("Origines bloquées (à ajouter à browser.allowed_origins si légitimes) : "
                     + ", ".join(_S.blocked))
    errors = sum(1 for m in _S.console if m.startswith(("[error]", "[pageerror]")))
    if errors:
        parts.append(f"{errors} erreur(s) console : voir browser_console")
    if snapshot:
        tree = await page.locator("body").aria_snapshot()
        parts.append("--- arbre d'accessibilité ---\n" + tree)
    return rt().clip("\n".join(parts))


async def _locate(selector: str):
    if not selector or len(selector) > 500:
        raise ToolError("selector vide ou trop long")
    page = await _S.page_()
    return page, page.locator(selector)


@tool("read")
async def browser_open(url: str) -> str:
    """Ouvre une URL dans le navigateur (Chromium sans fenêtre, sur la machine du MCP) et renvoie
    l'arbre d'accessibilité de la page. Autorisé : machines de hosts.yaml, localhost, et
    policies.yaml browser.allowed_origins. Ex. http://192.168.1.50:3000/login"""
    _check("read")
    async with _S.lock:
        if not _S._allowed(url):
            raise SecurityDenied(f"URL non autorisée : {url} (ajouter son origine à browser.allowed_origins "
                                 "dans policies.yaml)")
        page = await _S.page_()
        _S.blocked.clear()
        try:
            resp = await page.goto(url, wait_until="load")
        except Exception as exc:
            raise ToolError(f"navigation impossible : {str(exc).splitlines()[0]}")
        head = f"HTTP {resp.status}\n" if resp else ""
        return head + await _state(page)


@tool("read")
async def browser_snapshot() -> str:
    """Arbre d'accessibilité de la page courante (rôles, noms, textes) : à lire avant de cliquer."""
    _check("read")
    async with _S.lock:
        return await _state(await _S.page_())


@tool("read")
async def browser_screenshot(full_page: bool = False, selector: str | None = None) -> Image:
    """Capture PNG de la page courante (full_page=true : toute la hauteur ; selector : un seul élément)."""
    _check("read")
    async with _S.lock:
        if selector:
            _, loc = await _locate(selector)
            data = await loc.screenshot()
        else:
            data = await (await _S.page_()).screenshot(full_page=full_page)
        return Image(data=data, format="png")


@tool("read")
async def browser_console(clear: bool = False) -> str:
    """Messages console et erreurs JavaScript de la page depuis l'ouverture (300 derniers)."""
    _check("read")
    lines = list(_S.console)
    if clear:
        _S.console.clear()
    return rt().clip("\n".join(lines)) if lines else "(aucun message console)"


@tool("dev", read_only=False)
async def browser_click(selector: str) -> str:
    """Clique sur un élément. selector Playwright, ex. : role=button[name="Connexion"],
    text=Mot de passe oublié, #submit, a[href="/admin"]. Renvoie l'arbre de la page obtenue."""
    _check("dev")
    async with _S.lock:
        page, loc = await _locate(selector)
        try:
            await loc.click()
        except Exception as exc:
            raise ToolError(f"clic impossible : {str(exc).splitlines()[0]}")
        return await _state(page)


@tool("dev", read_only=False)
async def browser_fill(selector: str, value: str, submit: bool = False) -> str:
    """Remplit un champ (remplace son contenu). submit=true appuie ensuite sur Entrée.
    Ex. selector : role=textbox[name="Email"], input[name=q]. Ne jamais y saisir un vrai
    mot de passe de l'utilisateur : uniquement des identifiants de test."""
    _check("dev")
    async with _S.lock:
        page, loc = await _locate(selector)
        try:
            await loc.fill(value)
            if submit:
                await loc.press("Enter")
        except Exception as exc:
            raise ToolError(f"saisie impossible : {str(exc).splitlines()[0]}")
        return await _state(page)


@tool("dev", read_only=False)
async def browser_press(key: str, selector: str | None = None) -> str:
    """Appuie sur une touche (Enter, Escape, Tab, ArrowDown, Control+A…), sur un élément ou la page."""
    _check("dev")
    if not key or len(key) > 50:
        raise ToolError("touche invalide")
    async with _S.lock:
        if selector:
            page, loc = await _locate(selector)
            await loc.press(key)
        else:
            page = await _S.page_()
            await page.keyboard.press(key)
        return await _state(page)


@tool("read")
async def browser_close() -> str:
    """Ferme le navigateur (cookies et session effacés)."""
    _check("read")
    async with _S.lock:
        return "navigateur fermé" if await _S.close() else "aucun navigateur ouvert"
