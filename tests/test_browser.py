"""Outils browser_* : filtrage des origines et parcours réel dans Chromium (si Playwright est installé)."""

from __future__ import annotations

import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import yaml

from remotedev.config import load_config
from remotedev.runtime import Runtime, set_runtime
from remotedev.security.errors import SecurityDenied
from remotedev.tools import browser
from remotedev.tools.browser import url_allowed

PAGE = b"""<!doctype html><html><head><title>Demo</title></head><body>
<h1 id="t">Bonjour</h1>
<input aria-label="Nom" id="nom">
<button onclick="document.getElementById('t').textContent = 'Salut ' + document.getElementById('nom').value">
Valider</button>
<img src="http://10.255.255.1/pixel.png">
<script>console.error('boom')</script>
</body></html>"""


def test_url_allowed():
    machines = {"192.168.1.50"}
    assert url_allowed("http://localhost:3000/x", machines, [])
    assert url_allowed("https://192.168.1.50:8443/", machines, [])
    assert not url_allowed("http://192.168.1.51/", machines, [])
    assert not url_allowed("file:///C:/Windows/win.ini", machines, ["*"])
    assert not url_allowed("javascript:alert(1)", machines, [])
    assert url_allowed("https://app.exemple.fr/login", machines, ["https://app.exemple.fr"])
    assert not url_allowed("http://app.exemple.fr/login", machines, ["https://app.exemple.fr"])  # autre schéma
    assert not url_allowed("https://app.exemple.fr:8443/", machines, ["https://app.exemple.fr"])  # autre port
    assert url_allowed("http://cdn.exemple.fr:8080/a.js", machines, ["cdn.exemple.fr"])
    assert not url_allowed("https://evil.fr/?cdn.exemple.fr", machines, ["cdn.exemple.fr"])
    assert url_allowed("https://nimporte.org/", machines, ["*"])


def _setup(tmp_path, mode="dev", browser_cfg=None):
    proj = tmp_path / "p"
    proj.mkdir(parents=True)
    win = sys.platform == "win32"
    hosts = {"web": {"os": "windows" if win else "linux", "backend": "local",
                     "shell": "powershell" if win else "posix", "host": "192.168.1.50",
                     "permissions": ["read", "dev"], "allowed_paths": [str(proj).replace("\\", "/")]}}
    cdir = tmp_path / "cfg"
    cdir.mkdir(parents=True)
    (cdir / "hosts.yaml").write_text(yaml.safe_dump({"hosts": hosts}), encoding="utf-8")
    pol = {"mode": mode, "audit_log": str(tmp_path / "audit.log"), "browser": browser_cfg or {}}
    (cdir / "policies.yaml").write_text(yaml.safe_dump(pol), encoding="utf-8")
    set_runtime(Runtime(load_config(cdir)))


@pytest.mark.asyncio
async def test_denied_before_launch(tmp_path):
    _setup(tmp_path)
    with pytest.raises(SecurityDenied):
        await browser.browser_open("http://192.168.1.99/")
    _setup(tmp_path / "b", browser_cfg={"enabled": False})
    with pytest.raises(SecurityDenied):
        await browser.browser_open("http://localhost/")
    _setup(tmp_path / "c", mode="safe")
    with pytest.raises(SecurityDenied):
        await browser.browser_click("#x")


@pytest.fixture
def site():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(PAGE)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/"
    srv.shutdown()


@pytest.mark.asyncio
async def test_browser_roundtrip(tmp_path, site):
    pytest.importorskip("playwright")
    _setup(tmp_path)
    try:
        out = await browser.browser_open(site)
        if "Chromium introuvable" in out:
            pytest.skip("Chromium non installé")
        assert "HTTP 200" in out and "Titre : Demo" in out and 'heading "Bonjour"' in out
        assert "http://10.255.255.1:80" in out  # image externe bloquée et signalée
        out = await browser.browser_fill('role=textbox[name="Nom"]', "Ada")
        out = await browser.browser_click('role=button[name="Valider"]')
        assert 'heading "Salut Ada"' in out
        assert "boom" in await browser.browser_console()
        img = await browser.browser_screenshot()
        assert img.data[:8] == b"\x89PNG\r\n\x1a\n"
    finally:
        assert await browser.browser_close() == "navigateur fermé"
