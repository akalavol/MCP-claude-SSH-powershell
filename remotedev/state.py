"""État des instances en cours, partagé entre le serveur, la CLI et la mini-interface.

Chaque instance écrit logs/run/<pid>.json et le supprime en s'arrêtant. Un fichier dont
le processus n'existe plus est considéré comme périmé et nettoyé. L'arrêt se demande en
créant logs/run/<pid>.stop, que le serveur HTTP surveille : pas de signal, donc le même
comportement sous Windows et Linux, et cloudflared est arrêté proprement.

Le fichier d'une instance HTTP contient l'URL secrète : logs/run/ est réservé à l'utilisateur
local et ignoré par git.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any

BASE = Path(__file__).resolve().parent.parent
RUN_DIR = Path(os.environ.get("REMOTEDEV_RUN_DIR") or BASE / "logs" / "run")


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if sys.platform == "win32":
        # os.kill(pid, 0) TUE le processus sous Windows : on interroge l'API à la place.
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return False
            return code.value == 259  # STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _file(pid: int) -> Path:
    return RUN_DIR / f"{pid}.json"


def write(info: dict[str, Any]) -> None:
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    data = {"pid": os.getpid(), "updated_at": time.time(), **info}
    path = _file(data["pid"])
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    if sys.platform != "win32":
        os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def remove(pid: int | None = None) -> None:
    pid = pid or os.getpid()
    for suffix in (".json", ".stop", ".tmp"):
        try:
            (RUN_DIR / f"{pid}{suffix}").unlink()
        except FileNotFoundError:
            pass


def instances() -> list[dict[str, Any]]:
    """Instances vivantes (les fichiers périmés sont nettoyés au passage)."""
    out: list[dict[str, Any]] = []
    if not RUN_DIR.exists():
        return out
    for path in sorted(RUN_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            pid = int(data["pid"])
        except (ValueError, KeyError, OSError):
            continue
        if pid_alive(pid):
            out.append(data)
        else:
            remove(pid)
    return out


def request_stop(pid: int) -> bool:
    if not _file(pid).exists():
        return False
    (RUN_DIR / f"{pid}.stop").write_text("stop", encoding="utf-8")
    return True


def stop_requested(pid: int | None = None) -> bool:
    return (RUN_DIR / f"{pid or os.getpid()}.stop").exists()


def describe(inst: dict[str, Any]) -> str:
    """Résumé d'une ligne (sans l'URL secrète)."""
    kind = inst.get("transport", "?")
    parts = [f"pid {inst['pid']}", kind.upper(), f"mode {str(inst.get('mode', '?')).upper()}"]
    if kind == "http":
        left = int(inst.get("expires_at", 0) - time.time())
        parts.append(f"reste {max(0, left) // 60} min" if left > 0 else "expiration imminente")
        parts.append("tunnel" if inst.get("tunnel") else "local seulement")
    started = inst.get("started_at")
    if started:
        parts.append("depuis " + time.strftime("%H:%M", time.localtime(started)))
    return " · ".join(parts)
