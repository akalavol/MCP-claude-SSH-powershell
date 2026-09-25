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
        self.check_btn = ttk.Button(hosts_box, text="Tester les connexions", command=self.check_hosts)
        self.check_btn.pack(anchor="e", pady=(6, 0))

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
        try:
            from .config import load_config

            config = load_config()
        except Exception as exc:
            self.tree.insert("", "end", text="configuration", values=("KO", "", str(exc)[:200]))
            self.check_btn.state(["disabled"])
            return
        for name, h in sorted(config.hosts.items()):
            self.tree.insert("", "end", iid=name, text=name, values=("?", "", f"{h.os}/{h.backend}"))

    # -- actions
    def start(self) -> None:
        if self.allow_dev.get() and not self.messagebox.askyesno(
            "Mode DEV via Internet",
            "L'IA pourra écrire du code et l'exécuter sur vos machines, via une URL publique.\n"
            "Garder une durée courte. Continuer ?",
        ):
            return
        HTTP_LOG.parent.mkdir(parents=True, exist_ok=True)
        log = HTTP_LOG.open("a", encoding="utf-8")
        log.write(f"\n--- {time.strftime('%Y-%m-%d %H:%M:%S')} démarrage ---\n")
        log.flush()
        flags = 0x08000000 if sys.platform == "win32" else 0  # CREATE_NO_WINDOW
        self.last_error = ""
        self.proc = subprocess.Popen(build_command(self.minutes.get(), self.allow_dev.get(), self.tunnel.get()),
                         stdin=subprocess.DEVNULL, stdout=log, stderr=log, cwd=str(BASE),
                         creationflags=flags, start_new_session=sys.platform != "win32")
        log.close()
        self.launching_since = time.time()
        self.refresh(reschedule=False)

    def stop(self) -> None:
        for inst in state.instances():
            if inst.get("transport") == "http":
                state.request_stop(int(inst["pid"]))

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
