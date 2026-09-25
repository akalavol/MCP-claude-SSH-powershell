"""SSH_ASKPASS de RemoteDev : fournit à ssh le mot de passe enregistré d'une machine.

Lancé par ssh (via askpass.cmd) avec l'invite en argument. Ne répond qu'aux invites
de mot de passe : une question oui/non (empreinte d'hôte inconnue...) est refusée.
La machine et le dossier de config viennent de l'environnement posé par SSHBackend.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def main() -> int:
    prompt = " ".join(sys.argv[1:]).lower()
    if "password" not in prompt and "mot de passe" not in prompt:
        print(f"remotedev askpass : invite refusée : {prompt[:120]!r}", file=sys.stderr)
        return 1
    from remotedev import credentials

    secret = credentials.get_password(os.environ.get("RD_ASKPASS_HOST", ""),
                                      os.environ.get("RD_ASKPASS_CONFIG") or None)
    if secret is None:
        print("remotedev askpass : aucun mot de passe enregistré", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(secret.encode("utf-8") + b"\n")  # pas l'encodage de la console
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
