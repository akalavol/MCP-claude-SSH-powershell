"""Validation des identifiants passés par le modèle et masquage des secrets."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from .errors import SecurityDenied

_BRANCH_RE = re.compile(r"^(?!-)(?!.*\.\.)(?!.*//)(?!.*@\{)[A-Za-z0-9._/-]{1,200}(?<!\.lock)(?<![/.])$")
_CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SERVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}$")


def validate_branch(name: str) -> str:
    if not _BRANCH_RE.match(name or ""):
        raise SecurityDenied(f"nom de branche invalide : {name!r}")
    return name


def validate_container(name: str) -> str:
    if not _CONTAINER_RE.match(name or ""):
        raise SecurityDenied(f"nom de conteneur invalide : {name!r}")
    return name


def validate_service(name: str) -> str:
    if not _SERVICE_RE.match(name or ""):
        raise SecurityDenied(f"nom de service invalide : {name!r}")
    return name


def clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, int(value)))


# Motifs à haute précision uniquement : un motif générique (password=...) corromprait
# le code source que le modèle lit puis réécrit.
_REDACTIONS = [
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.S),
     "[REDACTED PRIVATE KEY]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED AWS KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "[REDACTED GITHUB TOKEN]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b"), "[REDACTED GITHUB TOKEN]"),
    (re.compile(r"\bsk-(ant-|proj-)?[A-Za-z0-9_-]{32,}\b"), "[REDACTED API KEY]"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED SLACK TOKEN]"),
]


def redact(text: str) -> str:
    for rx, repl in _REDACTIONS:
        text = rx.sub(repl, text)
    return text


def audit_params(params: dict[str, Any]) -> dict[str, Any]:
    """Paramètres journalisables : jamais de contenu de fichier ni de patch."""
    out: dict[str, Any] = {}
    for k, v in params.items():
        if k in ("content", "old_string", "new_string", "patch", "value") and isinstance(v, str):
            out[k] = {"len": len(v), "sha256": hashlib.sha256(v.encode()).hexdigest()[:16]}
        elif isinstance(v, str) and len(v) > 300:
            out[k] = v[:300] + "…"
        else:
            out[k] = v
    return out
