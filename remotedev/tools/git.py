"""Outils Git. push, reset --hard, clean, rebase et commit ne sont volontairement pas exposés."""

from __future__ import annotations

from ..runtime import rt, tool
from ..security.validator import clamp, validate_branch
from ._common import guard, run_argv

GIT = ["git", "--no-pager", "-c", "color.ui=never", "-c", "core.quotepath=off"]


def _secret_excludes() -> list[str]:
    return [f":(exclude,glob)**/{p}" for p in rt().policies.secret_patterns]


async def _git(host: str, project: str, args: list[str], level: str = "read", timeout: int | None = None,
               path_in_project: str | None = None) -> str:
    r = rt()
    h = r.host(host)
    r.require(h, level)
    p = r.project_path(h, project)
    body = guard(h, p, "list")
    if path_in_project:
        body += guard(h, r.path(h, path_in_project, "read"), "read", var="F")
    body += run_argv(h, GIT + args)
    res = await r.run(h, body, timeout=timeout)
    return r.format(res, f"git {args[0]} ({p})")


@tool("read")
async def git_status(host: str, project: str) -> str:
    """git status (branche, fichiers modifiés et non suivis)."""
    return await _git(host, project, ["status", "--short", "--branch", "--untracked-files=all"])


@tool("read")
async def git_diff(host: str, project: str, staged: bool = False, stat_only: bool = False,
                   file: str | None = None) -> str:
    """git diff du projet (staged=true pour l'index, stat_only=true pour le résumé).
    `file` : chemin absolu d'un fichier du projet pour restreindre le diff. Les fichiers secrets sont exclus."""
    args = ["diff"]
    if staged:
        args.append("--cached")
    if stat_only:
        args.append("--stat")
    args.append("--")
    args += [file] if file else ["."]
    args += _secret_excludes()
    return await _git(host, project, args, path_in_project=file)


@tool("read")
async def git_log(host: str, project: str, limit: int = 20) -> str:
    """Derniers commits (hash, date, auteur, message)."""
    n = clamp(limit, 1, 500)
    return await _git(host, project, ["log", f"-n{n}", "--date=short", "--pretty=format:%h %ad %an  %s"])


@tool("read")
async def git_branch(host: str, project: str) -> str:
    """Branches locales et distantes, avec la branche courante."""
    return await _git(host, project, ["branch", "-a", "-vv"])


@tool("dev", read_only=False)
async def git_pull(host: str, project: str) -> str:
    """git pull --ff-only (jamais de merge ni de rebase implicite)."""
    return await _git(host, project, ["pull", "--ff-only", "--no-rebase"], level="dev",
                      timeout=rt().policies.timeouts.git_pull)


@tool("dev", read_only=False)
async def git_checkout(host: str, project: str, branch: str, create: bool = False) -> str:
    """Change de branche (create=true pour en créer une). Git refuse s'il y a conflit avec des
    modifications locales : rien n'est écrasé (pas de --force)."""
    validate_branch(branch)
    args = ["checkout", "-b", branch] if create else ["checkout", branch, "--"]
    return await _git(host, project, args, level="dev")


@tool("dev", read_only=False, destructive=True)
async def restore_file(host: str, project: str, file: str) -> str:
    """Annule les modifications non commitées d'UN fichier suivi par git (git checkout -- fichier) :
    il reprend son contenu de l'index (le dernier état commité, ou indexé par l'utilisateur).
    Un fichier par appel, volontairement : restaurer tout le projet effacerait aussi le travail
    en cours de l'utilisateur. Sans effet sur un fichier non suivi (nouveau fichier)."""
    r = rt()
    h = r.host(host)
    r.require(h, "dev")
    p = r.project_path(h, project)
    f = r.path(h, file, "write")  # refuse secrets et .git avant tout appel distant
    body = guard(h, p, "list") + guard(h, f, "write", var="F")
    # Un fichier ordinaire seulement : un dossier restaurerait tout son contenu.
    if h.is_posix_shell:
        body += '[ -f "$F" ] || { echo "pas un fichier : $F" >&2; exit 2; }\n'
    else:
        body += "if (-not (Test-Path -LiteralPath $F -PathType Leaf)) { Rd-Fail 2 ('pas un fichier : ' + $F) }\n"
    # --literal-pathspecs : « * » ou « ? » dans le nom ne doivent jamais viser d'autres fichiers.
    body += run_argv(h, GIT + ["--literal-pathspecs", "checkout", "--", f])
    res = await r.run(h, body)
    return r.format(res, f"restore_file {f}")
