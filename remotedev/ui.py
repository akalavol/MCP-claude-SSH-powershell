"""Mini-interface (tkinter, fournie avec Python sous Windows) : état, démarrage/arrêt du
mode HTTP, test des machines, dernières actions de l'audit.

Aucun port n'est ouvert : l'interface lit logs/run/*.json et le journal d'audit, et
lance / arrête le serveur comme un processus séparé. Fermer la fenêtre n'arrête pas le
serveur (il a son propre arrêt automatique).
"""

from __future__ import annotations

import asyncio
import json
import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

from . import state

BASE = Path(__file__).resolve().parent.parent
SERVER = BASE / "server.py"
HTTP_LOG = BASE / "logs" / "http.log"
REFRESH_MS = 1000


# --- logique pure (testable sans affichage) ------------------------------------------

def mask_url(url: str) -> str:
    """https://x.trycloudflare.com/<secret>/mcp -> https://x.trycloudflare.com/••••••/mcp"""
    head, sep, rest = url.partition("://")
    if not sep:
        return url
    host, _, path = rest.partition("/")
    parts = path.split("/")
    if len(parts) >= 2:
        parts[0] = "••••••"
    return f"{head}://{host}/" + "/".join(parts)


def build_command(minutes: int, allow_dev: bool, tunnel: bool, port: int = 8765) -> list[str]:
    cmd = [sys.executable, str(SERVER), "--http", "--minutes", str(int(minutes)), "--port", str(int(port))]
    if allow_dev:
        cmd.append("--allow-dev")
    if not tunnel:
        cmd.append("--no-tunnel")
    return cmd


def launch_http(minutes: int, allow_dev: bool, tunnel: bool) -> subprocess.Popen:
    """Lance le mode HTTP en processus détaché (survit à la fermeture de l'interface)."""
    HTTP_LOG.parent.mkdir(parents=True, exist_ok=True)
    with HTTP_LOG.open("a", encoding="utf-8") as log:
        log.write(f"\n--- {time.strftime('%Y-%m-%d %H:%M:%S')} démarrage ---\n")
        log.flush()
        flags = 0x08000000 if sys.platform == "win32" else 0  # CREATE_NO_WINDOW
        return subprocess.Popen(build_command(minutes, allow_dev, tunnel), stdin=subprocess.DEVNULL,
                                stdout=log, stderr=log, cwd=str(BASE), creationflags=flags,
                                start_new_session=sys.platform != "win32")


def stop_http() -> int:
    n = 0
    for inst in state.instances():
        if inst.get("transport") == "http":
            n += state.request_stop(int(inst["pid"]))
    return n


def audit_tail(path: Path, n: int = 8) -> list[dict[str, Any]]:
    try:
        with path.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - 64 * 1024))
            lines = fh.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return []
    out = []
    for line in reversed(lines):
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
        if len(out) >= n:
            break
    return out


def format_audit(entry: dict[str, Any]) -> str:
    ts = str(entry.get("ts", ""))[11:19]
    via = " [http]" if entry.get("transport") == "http" else ""
    res = entry.get("result", "?")
    mark = {"SUCCESS": "OK", "DENIED": "REFUS", "ERROR": "ERREUR"}.get(res, res)
    return f"{ts}  {mark:<6} {entry.get('tool', '?'):<18} {entry.get('host') or '-':<16}{via}"


# Type de connexion affiché -> (backend, os, PowerShell distant)
CONNECTION_TYPES: dict[str, tuple[str, str, str | None]] = {
    "ssh-linux": ("ssh", "linux", None),
    "ssh-pwsh": ("ssh", "windows", "pwsh"),
    "ssh-ps51": ("ssh", "windows", "powershell"),
    "winrm": ("winrm", "windows", None),
    "local": ("local", "windows" if sys.platform == "win32" else "linux", None),
}
CONNECTION_LABELS = {
    "ssh-linux": "SSH → Linux (shell)",
    "ssh-pwsh": "SSH → Windows (PowerShell 7)",
    "ssh-ps51": "SSH → Windows (Windows PowerShell 5.1)",
    "winrm": "PowerShell Remoting (WinRM) → Windows",
    "local": "Ce PC (local)",
}
PASSWORD_LABEL = "Identifiant + mot de passe"
AUTH_DEFAULT_LABELS = {"ssh": "Clé SSH", "winrm": "Compte Windows actuel"}


def connection_kind(raw: dict[str, Any]) -> str:
    backend = "winrm" if raw.get("backend") == "powershell" else raw.get("backend", "ssh")
    if backend in ("winrm", "local"):
        return backend
    if raw.get("os") != "windows":
        return "ssh-linux"
    return "ssh-ps51" if raw.get("ps_exe") == "powershell" else "ssh-pwsh"


def form_to_host(form: dict[str, Any], existing: dict[str, Any] | None = None) -> dict[str, Any]:
    """Champs du formulaire -> entrée de hosts.yaml. Les champs non gérés par le formulaire
    (projects, docker, services, log_sources...) d'une entrée existante sont conservés."""
    data = dict(existing or {})
    for key in ("os", "backend", "host", "user", "port", "key", "ssh_alias", "winrm", "auth", "ps_exe",
                "host_key_sha256"):
        data.pop(key, None)
    backend, os_name, ps_exe = CONNECTION_TYPES[form["kind"]]
    if backend == "local" and existing and existing.get("backend") == "local":
        os_name = existing.get("os", os_name)
    elif data.get("shell") and os_name == "windows":
        data.pop("shell")  # le shell d'un hôte windows est forcément powershell
    password = backend != "local" and form.get("auth") == "password"
    data["os"] = os_name
    data["backend"] = backend
    if ps_exe == "powershell":
        data["ps_exe"] = ps_exe
    if password:
        data["auth"] = "password"
    if backend in ("ssh", "winrm"):
        skip = {"key", "ssh_alias"} if backend == "winrm" or password else set()
        if backend == "winrm" and not password:
            skip.add("user")  # compte Windows courant
        for key in ("host", "user", "key", "ssh_alias"):
            value = str(form.get(key) or "").strip()
            if value and key not in skip:
                data[key] = value.replace("\\", "/") if key == "key" else value
        port = str(form.get("port") or "").strip()
        if port:
            if not port.isdigit():
                raise ValueError(f"port invalide : {port!r}")
            data["port"] = int(port)
        fingerprint = str(form.get("host_key_sha256") or "").strip()
        if backend == "ssh" and fingerprint:
            data["host_key_sha256"] = fingerprint
        if backend == "winrm":
            winrm = dict((existing or {}).get("winrm") or {})
            winrm.pop("use_ssl", None)
            winrm.pop("port", None)
            if form.get("use_ssl"):
                winrm["use_ssl"] = True
            if "port" in data:  # le backend WinRM lit winrm.port
                winrm["port"] = data.pop("port")
            if winrm:
                data["winrm"] = winrm
    perms = ["read"] + (["dev"] if form.get("dev") else [])
    data["permissions"] = perms
    paths = [p.strip().replace("\\", "/") for p in str(form.get("allowed_paths") or "").splitlines() if p.strip()]
    if not paths:
        raise ValueError("indiquer au moins un dossier autorisé")
    data["allowed_paths"] = paths
    # ordre lisible dans le YAML
    order = ["os", "backend", "ps_exe", "host", "port", "user", "auth", "key", "ssh_alias", "host_key_sha256",
             "permissions",
             "allowed_paths"]
    return {k: data[k] for k in order if k in data} | {k: v for k, v in data.items() if k not in order}


def host_to_form(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": connection_kind(raw),
        "host": raw.get("host", ""), "user": raw.get("user", ""),
        "port": str(raw.get("port") or (raw.get("winrm") or {}).get("port") or ""), "key": raw.get("key", ""),
        "ssh_alias": raw.get("ssh_alias", ""),
        "host_key_sha256": raw.get("host_key_sha256", ""),
        "auth": raw.get("auth", "default"),
        "use_ssl": bool((raw.get("winrm") or {}).get("use_ssl")),
        "dev": "dev" in (raw.get("permissions") or []),
        "allowed_paths": "\n".join(raw.get("allowed_paths") or []),
    }


def http_log_tail(n: int = 4) -> str:
    try:
        lines = HTTP_LOG.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    return "\n".join(lines[-n:])


# --- interface ------------------------------------------------------------------------

def run_ui() -> None:
    import tkinter as tk
    from tkinter import messagebox, ttk

    app = RemoteDevUI(tk.Tk(), tk, ttk, messagebox)
    app.root.mainloop()


class RemoteDevUI:
    def __init__(self, root, tk, ttk, messagebox):
        self.root, self.tk, self.ttk, self.messagebox = root, tk, ttk, messagebox
        self.results: queue.Queue = queue.Queue()
        self.show_secret = False
        self.current_url = ""
        self.launching_since: float | None = None
        self.proc: subprocess.Popen | None = None
        self.last_error = ""
        self.audit_path = self._audit_path()

        root.title("RemoteDev")
        root.minsize(560, 560)
        pad = {"padx": 10, "pady": 4}

        # État
        top = ttk.Frame(root, padding=10)
        top.pack(fill="x")
        self.dot = tk.Canvas(top, width=18, height=18, highlightthickness=0)
        self.dot_id = self.dot.create_oval(2, 2, 16, 16, fill="gray", outline="")
        self.dot.pack(side="left")
        self.title = ttk.Label(top, text="HTTP : arrêté", font=("Segoe UI", 12, "bold"))
        self.title.pack(side="left", padx=8)
        self.subtitle = ttk.Label(root, text="", foreground="#555")
        self.subtitle.pack(fill="x", **pad)
        self.stdio_label = ttk.Label(root, text="")
        self.stdio_label.pack(fill="x", **pad)

        # URL
        url_box = ttk.LabelFrame(root, text="URL du connecteur (c'est le mot de passe)", padding=8)
        url_box.pack(fill="x", **pad)
        self.url_var = tk.StringVar(value="—")
        ttk.Entry(url_box, textvariable=self.url_var, state="readonly").pack(side="left", fill="x", expand=True)
        self.copy_btn = ttk.Button(url_box, text="Copier", command=self.copy_url)
        self.copy_btn.pack(side="left", padx=4)
        self.reveal_btn = ttk.Button(url_box, text="Afficher", command=self.toggle_secret)
        self.reveal_btn.pack(side="left")

        # Lancement
        run_box = ttk.LabelFrame(root, text="Mode HTTP à la demande", padding=8)
        run_box.pack(fill="x", **pad)
        ttk.Label(run_box, text="Durée (min)").grid(row=0, column=0, sticky="w")
        self.minutes = tk.IntVar(value=30)
        ttk.Spinbox(run_box, from_=5, to=240, increment=5, width=6, textvariable=self.minutes).grid(row=0, column=1, padx=6)
        self.tunnel = tk.BooleanVar(value=True)
        ttk.Checkbutton(run_box, text="Tunnel Cloudflare", variable=self.tunnel).grid(row=0, column=2, padx=6)
        self.allow_dev = tk.BooleanVar(value=False)
        ttk.Checkbutton(run_box, text="Autoriser l'écriture (DEV)", variable=self.allow_dev).grid(row=0, column=3, padx=6)
        self.start_btn = ttk.Button(run_box, text="Démarrer", command=self.start)
        self.start_btn.grid(row=1, column=0, columnspan=2, sticky="we", pady=(8, 0))
        self.stop_btn = ttk.Button(run_box, text="Arrêter", command=self.stop)
        self.stop_btn.grid(row=1, column=2, columnspan=2, sticky="we", pady=(8, 0))

        # Machines
        hosts_box = ttk.LabelFrame(root, text="Machines", padding=8)
        hosts_box.pack(fill="both", expand=True, **pad)
        self.tree = ttk.Treeview(hosts_box, columns=("etat", "latence", "detail"), height=5)
        for col, label, width in (("#0", "Machine", 140), ("etat", "État", 60), ("latence", "Latence", 70),
                                  ("detail", "Détail", 260)):
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width, stretch=col == "detail")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<Double-1>", lambda _e: self.edit_host())
        hosts_btns = ttk.Frame(hosts_box)
        hosts_btns.pack(fill="x", pady=(6, 0))
        ttk.Button(hosts_btns, text="Ajouter…", command=self.add_host).pack(side="left")
        ttk.Button(hosts_btns, text="Modifier…", command=self.edit_host).pack(side="left", padx=4)
        ttk.Button(hosts_btns, text="Supprimer", command=self.remove_host).pack(side="left")
        self.check_btn = ttk.Button(hosts_btns, text="Tester les connexions", command=self.check_hosts)
        self.check_btn.pack(side="right")

        # Activité
        act_box = ttk.LabelFrame(root, text="Dernières actions (audit)", padding=8)
        act_box.pack(fill="both", expand=True, **pad)
        self.activity = tk.Listbox(act_box, height=8, font=("Consolas", 9))
        self.activity.pack(fill="both", expand=True)

        self._load_hosts()
        self.refresh()

    # -- données
    def _audit_path(self) -> Path:
        try:
            from .config import load_config

            return Path(load_config().policies.audit_log)
        except Exception:
            return BASE / "logs" / "audit.log"

    def _load_hosts(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self.check_btn.state(["!disabled"])
        try:
            from .config import load_config

            config = load_config()
        except Exception as exc:
            self.tree.insert("", "end", text="configuration", values=("KO", "", str(exc)[:200]))
            self.check_btn.state(["disabled"])
            return
        if not config.hosts:
            self.tree.insert("", "end", text="(aucune)", values=("", "", "cliquer sur « Ajouter… »"))
            self.check_btn.state(["disabled"])
        for name, h in sorted(config.hosts.items()):
            target = h.ssh_alias or h.host or "ce PC"
            self.tree.insert("", "end", iid=name, text=name, values=("?", "", f"{h.os}/{h.backend} — {target}"))

    # -- gestion des machines
    def _selected_host(self) -> str | None:
        from .config import read_hosts_raw

        sel = self.tree.selection()
        if sel and sel[0] in read_hosts_raw():
            return sel[0]
        self.messagebox.showinfo("Machines", "Sélectionner d'abord une machine dans la liste.")
        return None

    def add_host(self) -> None:
        HostDialog(self, None)

    def edit_host(self) -> None:
        name = self._selected_host()
        if name:
            HostDialog(self, name)

    def remove_host(self) -> None:
        from .config import delete_host

        name = self._selected_host()
        if name and self.messagebox.askyesno("Supprimer", f"Retirer la machine « {name} » de hosts.yaml ?"):
            delete_host(name)
            self.hosts_changed()

    def hosts_changed(self) -> None:
        self._load_hosts()
        if state.instances():
            self.messagebox.showinfo(
                "Machines", "Enregistré. Les serveurs déjà lancés (HTTP ou Claude) doivent être "
                            "redémarrés pour voir la nouvelle liste.")

    # -- actions
    def start(self) -> None:
        if self.allow_dev.get() and not self.messagebox.askyesno(
            "Mode DEV via Internet",
            "L'IA pourra écrire du code et l'exécuter sur vos machines, via une URL publique.\n"
            "Garder une durée courte. Continuer ?",
        ):
            return
        self.last_error = ""
        self.proc = launch_http(self.minutes.get(), self.allow_dev.get(), self.tunnel.get())
        self.launching_since = time.time()
        self.refresh(reschedule=False)

    def stop(self) -> None:
        stop_http()

    def copy_url(self) -> None:
        if self.current_url:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.current_url)
            self.copy_btn.configure(text="Copié ✓")
            self.root.after(1500, lambda: self.copy_btn.configure(text="Copier"))

    def toggle_secret(self) -> None:
        self.show_secret = not self.show_secret
        self.reveal_btn.configure(text="Masquer" if self.show_secret else "Afficher")
        self.refresh(reschedule=False)

    def check_hosts(self) -> None:
        self.check_btn.state(["disabled"])
        for iid in self.tree.get_children():
            self.tree.set(iid, "etat", "…")

        def worker() -> None:
            try:
                from .config import load_config
                from .health import check_all

                self.results.put(("hosts", asyncio.run(check_all(load_config()))))
            except Exception as exc:
                self.results.put(("hosts_error", str(exc)))

        threading.Thread(target=worker, daemon=True).start()

    # -- affichage
    def refresh(self, reschedule: bool = True) -> None:
        insts = state.instances()
        http = next((i for i in insts if i.get("transport") == "http"), None)
        stdio = [i for i in insts if i.get("transport") == "stdio"]

        if http:
            self.launching_since = None
            running = http.get("status") == "en cours"
            self.dot.itemconfigure(self.dot_id, fill="#2e7d32" if running else "#ef8f00")
            self.title.configure(text=f"HTTP : {http.get('status', '?')}")
            self.subtitle.configure(text=state.describe(http))
            self.current_url = http.get("url", "")
            self.start_btn.state(["disabled"])
            self.stop_btn.state(["!disabled"])
        elif self.launching_since and self.proc is not None and self.proc.poll() is None \
                and time.time() - self.launching_since < 90:
            self.dot.itemconfigure(self.dot_id, fill="#ef8f00")
            self.title.configure(text="HTTP : démarrage…")
            self.subtitle.configure(text="")
            self.current_url = ""
            self.start_btn.state(["disabled"])
            self.stop_btn.state(["disabled"])
        else:
            if self.launching_since is not None:  # lancé, mais jamais arrivé à l'état « en cours »
                self.last_error = http_log_tail() or "échec : voir logs/http.log"
                self.launching_since = None
            self.dot.itemconfigure(self.dot_id, fill="#c62828" if self.last_error else "gray")
            self.title.configure(text="HTTP : échec du démarrage" if self.last_error else "HTTP : arrêté")
            self.subtitle.configure(text=self.last_error)
            self.current_url = ""
            self.start_btn.state(["!disabled"])
            self.stop_btn.state(["disabled"])

        shown = self.current_url if self.show_secret else mask_url(self.current_url)
        self.url_var.set(shown or "—")
        self.copy_btn.state(["!disabled"] if self.current_url else ["disabled"])

        if stdio:
            self.stdio_label.configure(
                text="Claude Desktop / Code (stdio) : actif — " + ", ".join(f"pid {i['pid']}" for i in stdio))
        else:
            self.stdio_label.configure(text="Claude Desktop / Code (stdio) : aucune instance")

        self.activity.delete(0, "end")
        for entry in audit_tail(self.audit_path):
            self.activity.insert("end", format_audit(entry))

        while not self.results.empty():
            kind, payload = self.results.get()
            if kind == "hosts":
                for h in payload:
                    if self.tree.exists(h.name):
                        self.tree.item(h.name, values=("OK" if h.ok else "KO", f"{h.seconds:.1f}s", h.detail))
            else:
                self.messagebox.showerror("Test des machines", payload)
            self.check_btn.state(["!disabled"])

        if reschedule:
            self.root.after(REFRESH_MS, self.refresh)


class HostDialog:
    """Fenêtre « Ajouter / Modifier une machine » : écrit config/hosts.yaml (+ credentials.dat)."""

    def __init__(self, ui: RemoteDevUI, name: str | None):
        from . import credentials
        from .config import read_hosts_raw

        self.ui, self.old_name = ui, name
        tk, ttk = ui.tk, ui.ttk
        self.existing = read_hosts_raw().get(name, {}) if name else {}
        self.has_saved_password = bool(name) and credentials.has_password(name)
        form = host_to_form(self.existing) if name else host_to_form({"os": "linux", "backend": "ssh"})

        self.win = win = tk.Toplevel(ui.root)
        win.title(f"Modifier « {name} »" if name else "Ajouter une machine")
        win.transient(ui.root)
        win.resizable(True, False)
        frm = ttk.Frame(win, padding=12)
        frm.pack(fill="both", expand=True)
        frm.columnconfigure(1, weight=1)

        self.vars: dict[str, Any] = {
            "name": tk.StringVar(value=name or ""),
            "kind": tk.StringVar(value=CONNECTION_LABELS[form["kind"]]),
            "auth": tk.StringVar(),
            "host": tk.StringVar(value=form["host"]),
            "user": tk.StringVar(value=form["user"]),
            "password": tk.StringVar(),
            "port": tk.StringVar(value=form["port"]),
            "key": tk.StringVar(value=form["key"]),
            "ssh_alias": tk.StringVar(value=form["ssh_alias"]),
            "host_key_sha256": tk.StringVar(value=form["host_key_sha256"]),
            "use_ssl": tk.BooleanVar(value=form["use_ssl"]),
            "dev": tk.BooleanVar(value=form["dev"]),
        }
        self._initial_auth = form["auth"]
        self.widgets: dict[str, list] = {}
        row = 0

        def line(label: str, widget, key: str | None = None, hint: str = "") -> None:
            nonlocal row
            lbl = ttk.Label(frm, text=label)
            lbl.grid(row=row, column=0, sticky="w", pady=3)
            widget.grid(row=row, column=1, sticky="we", pady=3)
            parts = [lbl, widget]
            if hint:
                h = ttk.Label(frm, text=hint, foreground="#777")
                h.grid(row=row, column=2, sticky="w", padx=6)
                parts.append(h)
            if key:
                self.widgets[key] = parts
            row += 1

        line("Nom", ttk.Entry(frm, textvariable=self.vars["name"]), hint="ex. serveur-maison")
        line("Type de connexion", ttk.Combobox(frm, textvariable=self.vars["kind"], state="readonly", width=40,
                                               values=tuple(CONNECTION_LABELS.values())))
        line("Hôte (IP ou nom)", ttk.Entry(frm, textvariable=self.vars["host"]), "host", "ex. 192.168.1.20")
        line("Port", ttk.Entry(frm, textvariable=self.vars["port"], width=8), "port", "vide = défaut")
        self.auth_box = ttk.Combobox(frm, textvariable=self.vars["auth"], state="readonly")
        line("Authentification", self.auth_box, "auth")
        line("Identifiant (login)", ttk.Entry(frm, textvariable=self.vars["user"]), "user")
        line("Mot de passe", ttk.Entry(frm, textvariable=self.vars["password"], show="•"), "password",
             "enregistré — vide = inchangé" if self.has_saved_password else "chiffré (compte Windows)")
        key_row = ttk.Frame(frm)
        ttk.Entry(key_row, textvariable=self.vars["key"]).pack(side="left", fill="x", expand=True)
        ttk.Button(key_row, text="…", width=3, command=self._browse_key).pack(side="left", padx=(4, 0))
        line("Clé SSH privée", key_row, "key", "fichier sans .pub")
        line("ou alias ~/.ssh/config", ttk.Entry(frm, textvariable=self.vars["ssh_alias"]), "ssh_alias",
             "remplace hôte/login/clé")
        line("Empreinte SHA256", ttk.Entry(frm, textvariable=self.vars["host_key_sha256"]), "host_key_sha256",
             "SHA256:… (recommandé)")
        line("", ttk.Label(frm, foreground="#777", wraplength=380, text=(
            "Sur la cible : ssh-keygen -lf C:\\ProgramData\\ssh\\ssh_host_ed25519_key.pub (Windows) ou "
            "/etc/ssh/ssh_host_ed25519_key.pub (Linux). Toute autre clé sera refusée.")), "fp_note")
        line("", ttk.Checkbutton(frm, text="HTTPS (WinRM sur 5986)", variable=self.vars["use_ssl"]), "use_ssl")
        line("", ttk.Label(frm, foreground="#777", wraplength=380, text=(
            "Hors domaine Active Directory, la machine doit être dans les TrustedHosts de ce PC "
            "(ou utiliser HTTPS) ; « Tester la connexion » le vérifie.")), "winrm_note")
        line("Droits", ttk.Checkbutton(frm, text="Autoriser l'écriture et les commandes (dev)",
                                       variable=self.vars["dev"]), hint="lecture toujours permise")

        ttk.Label(frm, text="Dossiers autorisés\n(un par ligne)").grid(row=row, column=0, sticky="nw", pady=3)
        self.paths = tk.Text(frm, height=4, width=46, font=("Consolas", 9))
        self.paths.insert("1.0", form["allowed_paths"])
        self.paths.grid(row=row, column=1, columnspan=2, sticky="we", pady=3)
        row += 1
        ttk.Label(frm, text="Claude ne pourra rien lire ni écrire en dehors de ces dossiers.",
                  foreground="#777").grid(row=row, column=1, columnspan=2, sticky="w")
        row += 1

        self.status = ttk.Label(frm, text="", wraplength=480)
        self.status.grid(row=row, column=0, columnspan=3, sticky="we", pady=(8, 0))
        row += 1
        btns = ttk.Frame(frm)
        btns.grid(row=row, column=0, columnspan=3, sticky="e", pady=(10, 0))
        self.test_btn = ttk.Button(btns, text="Tester la connexion", command=self._test)
        self.test_btn.pack(side="left")
        ttk.Button(btns, text="Annuler", command=win.destroy).pack(side="left", padx=6)
        ttk.Button(btns, text="Enregistrer", command=self._save).pack(side="left")

        self.vars["kind"].trace_add("write", lambda *_: self._toggle())
        self.vars["auth"].trace_add("write", lambda *_: self._toggle())
        self._toggle()
        win.grab_set()

    # -- helpers
    def _kind(self) -> str:
        label = self.vars["kind"].get()
        return next((k for k, v in CONNECTION_LABELS.items() if v == label), label)

    def _password_mode(self) -> bool:
        return self.vars["auth"].get() == PASSWORD_LABEL

    def _form(self) -> dict[str, Any]:
        f = {k: v.get() for k, v in self.vars.items()}
        f["kind"] = self._kind()
        f["auth"] = "password" if self._password_mode() else "default"
        f["allowed_paths"] = self.paths.get("1.0", "end")
        return f

    def _build(self) -> tuple[str, dict[str, Any]]:
        from .config import HostConfig

        f = self._form()
        name = f["name"].strip()
        if not name:
            raise ValueError("donner un nom à la machine")
        data = form_to_host(f, self.existing)
        HostConfig.model_validate({**data, "name": name})  # erreur affichée avant d'écrire
        if data.get("auth") == "password" and not f["password"] and not (
                self.has_saved_password and name == self.old_name):
            raise ValueError("saisir le mot de passe")
        return name, data

    def _toggle(self) -> None:
        backend = CONNECTION_TYPES[self._kind()][0]
        if backend in AUTH_DEFAULT_LABELS:
            choices = (AUTH_DEFAULT_LABELS[backend], PASSWORD_LABEL)
            self.auth_box.configure(values=choices)
            if self.vars["auth"].get() not in choices:
                self.vars["auth"].set(PASSWORD_LABEL if self._initial_auth == "password" else choices[0])
                return  # le trace sur auth rappelle _toggle
        password = self._password_mode()
        visible = {
            "ssh": {"host", "port", "auth", "user", "host_key_sha256", "fp_note"}
                   | ({"password"} if password else {"key", "ssh_alias"}),
            "winrm": {"host", "port", "auth", "use_ssl", "winrm_note"} | ({"user", "password"} if password else set()),
            "local": set(),
        }[backend]
        for key, parts in self.widgets.items():
            for w in parts:
                if key in visible:
                    w.grid()
                else:
                    w.grid_remove()

    def _browse_key(self) -> None:
        from tkinter import filedialog

        path = filedialog.askopenfilename(parent=self.win, title="Clé SSH privée",
                                          initialdir=str(Path.home() / ".ssh"))
        if path:
            self.vars["key"].set(path)

    def _error(self, exc: Exception) -> None:
        msg = str(exc)
        if "validation error" in msg:  # pydantic : garder les lignes utiles
            msg = "\n".join(s.split(" [type=")[0].strip().removeprefix("Value error, ")
                            for s in msg.splitlines()[1:] if s.strip() and "further information" not in s)
        self.status.configure(text=msg, foreground="#c62828")

    # -- actions
    def _test(self) -> None:
        import tempfile

        from . import credentials
        from .config import HostConfig, resolve_config_dir
        from .health import check_host

        try:
            name, data = self._build()
            host = HostConfig.model_validate({**data, "name": name})
            if host.auth == "password":
                typed = self.vars["password"].get()
                if typed:  # mot de passe pas encore enregistré : dossier temporaire
                    tmp = tempfile.mkdtemp(prefix="remotedev-test-")
                    credentials.set_password(name, typed, tmp)
                    host._config_dir = Path(tmp)
                else:
                    host._config_dir = resolve_config_dir()
        except Exception as exc:
            self._error(exc)
            return
        self.status.configure(text="Test en cours…", foreground="#555")
        self.test_btn.state(["disabled"])
        result: queue.Queue = queue.Queue()

        def worker() -> None:
            try:
                result.put(asyncio.run(check_host(host)))
            except Exception as exc:
                result.put(exc)
            finally:
                if host.auth == "password" and self.vars["password"].get():
                    import shutil

                    shutil.rmtree(host._config_dir, ignore_errors=True)

        def poll() -> None:
            if not self.win.winfo_exists():
                return
            if result.empty():
                self.win.after(200, poll)
                return
            res = result.get()
            self.test_btn.state(["!disabled"])
            if isinstance(res, Exception):
                self._error(res)
            elif res.ok:
                self.status.configure(text=f"Connexion OK : {res.detail} ({res.seconds:.1f}s)", foreground="#2e7d32")
            else:
                self.status.configure(text=f"Échec : {res.detail}{connection_hint(res.detail)}", foreground="#c62828")

        threading.Thread(target=worker, daemon=True).start()
        poll()

    def _save(self) -> None:
        from . import credentials
        from .config import save_host

        try:
            name, data = self._build()
            save_host(name, data, old_name=self.old_name)
            if data.get("auth") == "password" and self.vars["password"].get():
                credentials.set_password(name, self.vars["password"].get())
        except Exception as exc:
            self._error(exc)
            return
        self.win.destroy()
        self.ui.hosts_changed()


def connection_hint(detail: str) -> str:
    """Conseil pour les erreurs de connexion les plus fréquentes."""
    d = detail.lower()
    if "host key verification failed" in d:
        return ("\nClé du serveur inconnue ou modifiée : renseigner « Empreinte SHA256 » (relevée sur la cible), "
                "ou lancer une fois « ssh login@hôte » dans un terminal et vérifier l'empreinte avant « yes ».")
    if "empreinte refusée" in d:
        return ("\nLe serveur ne présente pas la clé attendue : revérifier l'empreinte sur la cible. "
                "Si elle n'a pas changé, ne pas se connecter (possible interception).")
    if "permission denied" in d:
        return "\nIdentifiant, mot de passe ou clé refusé par le serveur."
    if "trustedhosts" in d:
        return ("\nAjouter la machine aux TrustedHosts (PowerShell administrateur) : "
                "Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value <hôte> -Concatenate")
    if "'pwsh' is not recognized" in d or "pwsh: not found" in d or "pwsh : " in d:
        return "\nPowerShell 7 absent sur la cible : choisir « SSH → Windows (Windows PowerShell 5.1) »."
    return ""


