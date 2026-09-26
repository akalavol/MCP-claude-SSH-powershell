"""Mots de passe des machines (auth: password), chiffrés avec DPAPI Windows.

Stockés dans config/credentials.dat (ignoré par git), jamais dans hosts.yaml. Le
chiffrement DPAPI est lié au compte Windows : seul ce compte, sur ce PC, peut les
relire. Hors Windows, aucun stockage (utiliser une clé SSH).
"""

from __future__ import annotations

import base64
import ctypes
import json
import os
import sys
from ctypes import wintypes
from pathlib import Path

from .config import resolve_config_dir

FILE_NAME = "credentials.dat"
_ENTROPY = b"remotedev-credentials-v1"


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi(data: bytes, protect: bool) -> bytes:
    if sys.platform != "win32":
        raise RuntimeError("mot de passe enregistré : uniquement sous Windows (utiliser une clé SSH)")
    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    src = ctypes.create_string_buffer(data, len(data))
    ent = ctypes.create_string_buffer(_ENTROPY, len(_ENTROPY))
    blob_in = _Blob(len(data), ctypes.cast(src, ctypes.POINTER(ctypes.c_char)))
    blob_ent = _Blob(len(_ENTROPY), ctypes.cast(ent, ctypes.POINTER(ctypes.c_char)))
    blob_out = _Blob()
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    # 0x1 = CRYPTPROTECT_UI_FORBIDDEN
    if not fn(ctypes.byref(blob_in), None, ctypes.byref(blob_ent), None, None, 0x1, ctypes.byref(blob_out)):
        raise OSError(ctypes.get_last_error() or "échec DPAPI")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)


def protect(secret: str) -> bytes:
    return _dpapi(secret.encode("utf-8"), True)


def unprotect(blob: bytes) -> str:
    return _dpapi(blob, False).decode("utf-8")


def _path(config_dir: str | os.PathLike | None) -> Path:
    return resolve_config_dir(config_dir) / FILE_NAME


def _load(config_dir: str | os.PathLike | None) -> dict[str, str]:
    try:
        return json.loads(_path(config_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save(data: dict[str, str], config_dir: str | os.PathLike | None) -> None:
    path = _path(config_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(FILE_NAME + ".tmp")
    tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
    os.replace(tmp, path)


def blob(name: str, config_dir: str | os.PathLike | None = None) -> bytes | None:
    """Mot de passe chiffré (DPAPI) de la machine, tel que stocké."""
    value = _load(config_dir).get(name)
    return base64.b64decode(value) if value else None


def has_password(name: str, config_dir: str | os.PathLike | None = None) -> bool:
    return name in _load(config_dir)


def get_password(name: str, config_dir: str | os.PathLike | None = None) -> str | None:
    b = blob(name, config_dir)
    return unprotect(b) if b else None


def set_password(name: str, secret: str, config_dir: str | os.PathLike | None = None) -> None:
    data = _load(config_dir)
    data[name] = base64.b64encode(protect(secret)).decode("ascii")
    _save(data, config_dir)


def delete_password(name: str, config_dir: str | os.PathLike | None = None) -> None:
    data = _load(config_dir)
    if data.pop(name, None) is not None:
        _save(data, config_dir)


def rename(old: str, new: str, config_dir: str | os.PathLike | None = None) -> None:
    data = _load(config_dir)
    if old in data:
        data[new] = data.pop(old)
        _save(data, config_dir)
