"""État des instances, CLI status/stop, et mini-interface."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from conftest import ROOT, write_config
from remotedev import state, ui


@pytest.fixture
def run_dir(tmp_path, monkeypatch):
    d = tmp_path / "run"
    monkeypatch.setattr(state, "RUN_DIR", d)
    monkeypatch.setenv("REMOTEDEV_RUN_DIR", str(d))
    return d


def test_state_lifecycle(run_dir):
    state.write({"transport": "http", "mode": "safe", "status": "en cours", "url": "https://a/b/mcp",
                 "started_at": time.time(), "expires_at": time.time() + 600, "tunnel": True})
    insts = state.instances()
    assert len(insts) == 1 and insts[0]["pid"] == os.getpid()
    assert "HTTP" in state.describe(insts[0]) and "https" not in state.describe(insts[0])
    assert state.request_stop(os.getpid()) and state.stop_requested()
    state.remove()
    assert state.instances() == [] and not any(run_dir.iterdir())


def test_stale_state_is_cleaned(run_dir):
    run_dir.mkdir()
    dead = subprocess.Popen([sys.executable, "-c", "pass"])
    dead.wait()
    (run_dir / f"{dead.pid}.json").write_text(json.dumps({"pid": dead.pid, "transport": "http"}))
    assert state.instances() == []
    assert not (run_dir / f"{dead.pid}.json").exists()


def test_ui_helpers(tmp_path):
    assert ui.mask_url("https://x.trycloudflare.com/SECRET123/mcp") == "https://x.trycloudflare.com/••••••/mcp"
    cmd = ui.build_command(20, allow_dev=True, tunnel=False)
    assert cmd[-5:] == ["20", "--port", "8765", "--allow-dev", "--no-tunnel"]
    assert "--allow-dev" not in ui.build_command(20, allow_dev=False, tunnel=True)
    log = tmp_path / "audit.log"
    log.write_text("\n".join(json.dumps({"ts": f"2026-09-25T09:00:0{i}+00:00", "tool": f"t{i}", "host": "h",
                                          "result": "SUCCESS"}) for i in range(5)) + "\nnot json\n")
    tail = ui.audit_tail(log, n=3)
    assert [e["tool"] for e in tail] == ["t4", "t3", "t2"]
    assert "OK" in ui.format_audit(tail[0]) and "09:00:04" in ui.format_audit(tail[0])


def test_host_form_and_save(tmp_path):
    from remotedev.config import delete_host, load_config, read_hosts_raw, save_host

    cdir = tmp_path / "cfg"
    form = {"kind": "ssh-linux", "host": "192.168.1.20", "user": "claude-dev", "port": "2222",
            "key": r"C:\Users\me\.ssh\claude_dev", "ssh_alias": "", "use_ssl": False, "dev": True,
            "allowed_paths": "/home/claude-dev/projects/a\n\n  /home/claude-dev/projects/b \n"}
    data = ui.form_to_host(form)
    assert data["port"] == 2222 and data["key"] == "C:/Users/me/.ssh/claude_dev"
    assert data["permissions"] == ["read", "dev"] and len(data["allowed_paths"]) == 2
    save_host("srv", data, config_dir=cdir)
    assert load_config(cdir).hosts["srv"].host == "192.168.1.20"

    # modification + renommage : les champs hors formulaire sont conservés
    raw = {**read_hosts_raw(cdir)["srv"], "docker": {"enabled": True}}
    local = ui.form_to_host({**ui.host_to_form(raw), "kind": "local", "dev": False,
                                                            "allowed_paths": str(tmp_path)}, raw)
    assert "host" not in local and local["docker"] == {"enabled": True} and local["permissions"] == ["read"]
    save_host("srv2", local, old_name="srv", config_dir=cdir)
    assert list(read_hosts_raw(cdir)) == ["srv2"] and (cdir / "hosts.yaml.bak").exists()

    with pytest.raises(ValueError):
        save_host("bad", {**data, "allowed_paths": ["/"]}, config_dir=cdir)
    with pytest.raises(ValueError):
        ui.form_to_host({**form, "allowed_paths": "  "})
    # PowerShell Remoting : Windows forcé, port et HTTPS rangés sous winrm:, pas d'utilisateur
    win = ui.form_to_host({**form, "kind": "winrm", "use_ssl": True,
                           "allowed_paths": "C:\\Projet\\Test"})
    assert win["os"] == "windows" and "user" not in win and "port" not in win
    assert win["winrm"] == {"use_ssl": True, "port": 2222}
    assert ui.host_to_form(win)["port"] == "2222"
    save_host("pc-win", win, config_dir=cdir)
    assert load_config(cdir).hosts["pc-win"].winrm.port == 2222
    delete_host("pc-win", config_dir=cdir)

    # SSH vers Windows PowerShell 5.1
    ps51 = ui.form_to_host({**form, "kind": "ssh-ps51", "allowed_paths": "C:/Projet"})
    assert ps51["os"] == "windows" and ps51["ps_exe"] == "powershell"
    assert ui.host_to_form(ps51)["kind"] == "ssh-ps51"
    assert ui.host_to_form({**ps51, "ps_exe": "pwsh"})["kind"] == "ssh-pwsh"

    delete_host("srv2", config_dir=cdir)
    assert load_config(cdir).hosts == {}


@pytest.mark.skipif(sys.platform != "win32", reason="DPAPI : Windows uniquement")
def test_password_auth(tmp_path):
    from remotedev import credentials
    from remotedev.backends.powershell_backend import WinRMBackend
    from remotedev.backends.ssh_backend import SSHBackend
    from remotedev.config import delete_host, load_config, save_host

    cdir = tmp_path / "cfg"
    base = {"kind": "ssh-linux", "host": "10.0.0.5", "user": "bob", "port": "", "key": "C:/k", "ssh_alias": "",
            "use_ssl": False, "dev": False, "allowed_paths": "/srv/app", "auth": "password"}
    data = ui.form_to_host(base)
    assert data["auth"] == "password" and "key" not in data  # la clé est ignorée en mode mot de passe
    with pytest.raises(ValueError):  # identifiant obligatoire
        save_host("x", ui.form_to_host({**base, "user": ""}), config_dir=cdir)
    save_host("srv", data, config_dir=cdir)
    credentials.set_password("srv", "p@ss 'é", cdir)
    assert "p@ss" not in (cdir / "credentials.dat").read_text()
    assert "p@ss" not in (cdir / "hosts.yaml").read_text()

    host = load_config(cdir).hosts["srv"]
    ssh = SSHBackend(host)
    argv, env = ssh.ssh_argv(), ssh.env()
    assert "BatchMode=no" in argv and "-i" not in argv and not any("p@ss" in a for a in argv)
    assert env["SSH_ASKPASS_REQUIRE"] == "force" and env["RD_ASKPASS_HOST"] == "srv"
    askpass = [sys.executable, str(ROOT / "remotedev" / "askpass.py")]
    out = subprocess.run(askpass + ["bob@10.0.0.5's password:"], env=env, capture_output=True)
    assert out.returncode == 0 and out.stdout == "p@ss 'é\n".encode("utf-8")  # UTF-8 quelle que soit la console
    out = subprocess.run(askpass + ["Are you sure you want to continue connecting (yes/no)?"], env=env,
                         capture_output=True, text=True)
    assert out.returncode == 1 and out.stdout == ""

    save_host("pc", ui.form_to_host({**base, "kind": "winrm", "allowed_paths": "C:/P"}), config_dir=cdir)
    credentials.set_password("pc", "w1n", cdir)
    wrapper = WinRMBackend(load_config(cdir).hosts["pc"]).wrapper("Write-Output 1")
    assert "Credential = $__cred" in wrapper and "w1n" not in wrapper

    # repasser en authentification par défaut efface le mot de passe
    save_host("srv", ui.form_to_host({**base, "auth": "default"}), old_name="srv", config_dir=cdir)
    assert not credentials.has_password("srv", cdir)
    delete_host("pc", config_dir=cdir)
    assert not credentials.has_password("pc", cdir)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_http_start_status_stop(tmp_path, run_dir):
    proj = tmp_path / "p" / "demo"
    proj.mkdir(parents=True)
    cdir = write_config(tmp_path / "cfg", proj, tmp_path / "audit.log", mode="dev")
    env = {**os.environ, "REMOTEDEV_CONFIG_DIR": str(cdir), "REMOTEDEV_RUN_DIR": str(run_dir)}
    port = _free_port()
    proc = subprocess.Popen([sys.executable, str(ROOT / "server.py"), "--http", "--no-tunnel",
                             "--port", str(port), "--minutes", "5"],
                            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.time() + 30
        inst = None
        while time.time() < deadline:
            insts = state.instances()
            if insts and insts[0].get("status") == "en cours":
                inst = insts[0]
                break
            time.sleep(0.2)
        assert inst, "le serveur n'a pas publié son état"
        assert inst["mode"] == "safe"  # SAFE forcé sans --allow-dev
        assert inst["url"].startswith(f"http://127.0.0.1:{port}/") and inst["url"].endswith("/mcp")

        out = subprocess.run([sys.executable, str(ROOT / "server.py"), "--status"], env=env,
                             capture_output=True, text=True, timeout=30).stdout
        assert f"pid {proc.pid}" in out and "en cours" in out

        subprocess.run([sys.executable, str(ROOT / "server.py"), "--stop"], env=env, check=True, timeout=30)
        assert proc.wait(timeout=15) == 0
        assert state.instances() == []
        assert "arrêt demandé" in proc.stderr.read().decode()
    finally:
        if proc.poll() is None:
            proc.kill()


def test_ui_window(tmp_path, run_dir, monkeypatch):
    tk = pytest.importorskip("tkinter")
    if sys.platform != "win32" and not os.environ.get("DISPLAY"):
        pytest.skip("pas d'affichage (lancer sous xvfb-run)")
    from tkinter import messagebox, ttk

    proj = tmp_path / "p" / "demo"
    proj.mkdir(parents=True)
    monkeypatch.setenv("REMOTEDEV_CONFIG_DIR", str(write_config(tmp_path / "cfg", proj, tmp_path / "audit.log")))
    (tmp_path / "audit.log").write_text(json.dumps({"ts": "2026-09-25T10:11:12+00:00", "tool": "read_file",
                                                     "host": "local-sh", "result": "DENIED"}) + "\n")
    root = tk.Tk()
    try:
        app = ui.RemoteDevUI(root, tk, ttk, messagebox)
        app.refresh(reschedule=False)
        assert app.title.cget("text") == "HTTP : arrêté"
        assert "aucune instance" in app.stdio_label.cget("text")
        assert "read_file" in app.activity.get(0)
        assert set(app.tree.get_children()) >= {"local-sh", "local-ps"}

        state.write({"transport": "http", "mode": "safe", "status": "en cours", "tunnel": True,
                     "url": "https://x.trycloudflare.com/SECRET/mcp", "started_at": time.time(),
                     "expires_at": time.time() + 1800})
        app.refresh(reschedule=False)
        assert app.title.cget("text") == "HTTP : en cours"
        assert app.url_var.get() == "https://x.trycloudflare.com/••••••/mcp"
        assert "disabled" in app.start_btn.state()
        app.toggle_secret()
        assert "SECRET" in app.url_var.get()
        app.copy_url()
        assert root.clipboard_get() == "https://x.trycloudflare.com/SECRET/mcp"

        app.check_hosts()
        deadline = time.time() + 30
        while time.time() < deadline and app.tree.set("local-sh", "etat") in ("?", "…"):
            app.refresh(reschedule=False)
            root.update()
            time.sleep(0.2)
        assert app.tree.set("local-sh", "etat") == "OK"

        app.stop()
        assert state.stop_requested()
    finally:
        state.remove()
        root.destroy()


def test_host_key_pinning(tmp_path, monkeypatch):
    import asyncio
    import base64
    import hashlib

    from remotedev import hostkey
    from remotedev.backends import ssh_backend
    from remotedev.backends.base import ExecResult
    from remotedev.config import load_config, save_host

    good, other = base64.b64encode(b"\x00cle-ed25519").decode(), base64.b64encode(b"\x00cle-rsa").decode()
    fp = "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(good)).digest()).decode().rstrip("=")
    assert hostkey.normalize_fingerprint(fp[7:] + "=") == fp
    with pytest.raises(ValueError):
        hostkey.normalize_fingerprint("SHA256:trop-court")

    cdir = tmp_path / "cfg"
    form = {"kind": "ssh-linux", "host": "10.0.0.5", "user": "bob", "port": "2222", "key": "", "ssh_alias": "",
            "use_ssl": False, "dev": False, "allowed_paths": "/srv/app", "host_key_sha256": f"  {fp[7:]} "}
    data = ui.form_to_host(form)
    assert ui.host_to_form(data)["host_key_sha256"] == fp[7:]
    assert "host_key_sha256" not in ui.form_to_host({**form, "kind": "winrm", "allowed_paths": "C:/P"})
    with pytest.raises(ValueError):  # un alias ~/.ssh/config gère sa propre clé d'hôte
        save_host("x", {**data, "ssh_alias": "srv"}, config_dir=cdir)
    save_host("srv", data, config_dir=cdir)
    host = load_config(cdir).hosts["srv"]
    assert host.host_key_sha256 == fp

    ssh = ssh_backend.SSHBackend(host)
    argv = ssh.ssh_argv()
    assert "StrictHostKeyChecking=yes" in argv and "HostKeyAlias=remotedev-srv" in argv
    assert f'UserKnownHostsFile="{(cdir / "known_hosts").as_posix()}"' in argv

    scans: list[list[str]] = []
    presented = [f"[10.0.0.5]:2222 ssh-rsa {other}", f"[10.0.0.5]:2222 ssh-ed25519 {good}"]

    async def fake_run(argv, stdin, timeout, env=None):
        scans.append(argv)
        return ExecResult(0, "# commentaire\n" + "\n".join(presented) + "\n", "", 0.1)

    monkeypatch.setattr(ssh_backend, "run_process", fake_run)
    asyncio.run(ssh.ensure_host_key())
    assert scans[0][-3:] == ["-p", "2222", "10.0.0.5"]
    assert (cdir / "known_hosts").read_text() == f"remotedev-srv ssh-ed25519 {good}\n"
    asyncio.run(ssh.ensure_host_key())  # déjà épinglée : pas de nouveau scan
    assert len(scans) == 1

    presented = [f"[10.0.0.5]:2222 ssh-rsa {other}"]  # autre clé : refus, rien n'est écrit
    host.host_key_sha256 = hostkey.normalize_fingerprint("A" * 43)
    with pytest.raises(RuntimeError, match="empreinte refusée"):
        asyncio.run(ssh.ensure_host_key())
    assert (cdir / "known_hosts").read_text() == f"remotedev-srv ssh-ed25519 {good}\n"
    assert "empreinte" in ui.connection_hint("empreinte refusée : le serveur présente …")
