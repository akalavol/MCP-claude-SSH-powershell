"""Épinglage de la clé d'hôte SSH sur une empreinte SHA256 saisie dans la config.

La clé est lue avec ssh-keyscan (non authentifié), mais n'est écrite dans
config/known_hosts que si son empreinte est exactement celle attendue. ssh est ensuite
lancé avec StrictHostKeyChecking=yes sur ce fichier : une clé différente est refusée.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
from pathlib import Path

_FP_RE = re.compile(r"^(?:SHA256:)?([A-Za-z0-9+/]{43})=?$")


def normalize_fingerprint(value: str) -> str:
    """'SHA256:abc…' ou 'abc…' (43 caractères base64, tel qu'affiché par ssh-keygen -lf)."""
    m = _FP_RE.match(value.strip())
    if not m:
        raise ValueError(f"empreinte SHA256 invalide : {value!r} (attendu : SHA256: suivi de 43 caractères, "
                         "tel qu'affiché par ssh-keygen -lf)")
    return "SHA256:" + m.group(1)


def fingerprint(key_b64: str) -> str | None:
    try:
        blob = base64.b64decode(key_b64, validate=True)
    except (binascii.Error, ValueError):
        return None
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")


def alias(host_name: str) -> str:
    """Nom sous lequel la clé est rangée (HostKeyAlias) : indépendant de l'IP et du port."""
    return f"remotedev-{host_name}"


def _entries(path: Path) -> list[list[str]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    return [parts for parts in (line.split() for line in lines) if len(parts) >= 3 and not parts[0].startswith("#")]


def is_pinned(path: Path, name: str, expected: str) -> bool:
    return any(p[0] == name and fingerprint(p[2]) == expected for p in _entries(path))


def find_key(keyscan_output: str, expected: str) -> tuple[tuple[str, str] | None, list[str]]:
    """(type, clé) dont l'empreinte vaut `expected`, et la liste des empreintes présentées."""
    seen: list[str] = []
    for parts in (line.split() for line in keyscan_output.splitlines()):
        if len(parts) < 3 or parts[0].startswith("#"):
            continue
        fp = fingerprint(parts[2])
        if fp is None:
            continue
        if fp == expected:
            return (parts[1], parts[2]), seen
        seen.append(f"{parts[1]} {fp}")
    return None, seen


def pin(path: Path, name: str, key_type: str, key_b64: str) -> None:
    """Remplace les clés rangées sous `name` par celle-ci (écriture atomique)."""
    keep = [" ".join(p) for p in _entries(path) if p[0] != name]
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text("\n".join(keep + [f"{name} {key_type} {key_b64}"]) + "\n", encoding="utf-8")
    os.replace(tmp, path)
