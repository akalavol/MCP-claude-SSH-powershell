"""Liste noire de commandes.

Ne s'applique qu'aux commandes *textuelles* venant de la configuration (test/build
personnalisés). Les scripts générés par le MCP n'interpolent jamais de texte fourni
par le modèle autrement que quoté comme donnée, et aucun outil n'exécute de commande
arbitraire. Cette liste est un filet, pas une frontière de sécurité : `npm test`
exécute déjà n'importe quel code écrit dans le projet.
"""

from __future__ import annotations

import re

from .errors import SecurityDenied

DEFAULT_BLOCKED = [
    r"\brm\s+(-[a-zA-Z]*\s+)*-[a-zA-Z]*[rR][a-zA-Z]*\s+(-[a-zA-Z]*\s+)*/(\*|\s|$)",
    r"\bmkfs(\.\w+)?\b",
    r"\bdd\s+if=",
    r"\b(shutdown|poweroff|reboot|halt)\b",
    r"\b(passwd|userdel|usermod|useradd|chpasswd)\b",
    r"\bsudo\b",
    r"\bsu\s+-",
    r"\bchmod\s+(-R\s+)?[0-7]*777\s+/",
    r"\bdel\s+/s\s+/q\s+[a-z]:\\",
    r"(?i)\bremove-item\s+[a-z]:\\?\s.*-recurse",
    r"(?i)\b(format-volume|clear-disk|remove-partition|initialize-disk)\b",
    r"(?i)\b(stop-computer|restart-computer)\b",
    r"(?i)\bset-executionpolicy\s+(unrestricted|bypass)\b",
    r"(?i)\bformat\s+[a-z]:",
    r"(?i)\breg\s+(delete|add)\s+hklm",
    r"\bcurl\b[^|]*\|\s*(ba|z)?sh\b",
    r"\bwget\b[^|]*\|\s*(ba|z)?sh\b",
    r"(?i)\biex\s*\(\s*(new-object|iwr|invoke-webrequest)",
]


def check_command(command: str, extra_patterns: list[str] | None = None) -> None:
    for pat in DEFAULT_BLOCKED + list(extra_patterns or []):
        if re.search(pat, command, flags=re.IGNORECASE):
            raise SecurityDenied(f"commande bloquée par la politique ({pat})")
