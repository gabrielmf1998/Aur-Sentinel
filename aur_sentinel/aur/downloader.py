from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from aur_sentinel.utils.paths import AuditPaths, create_audit_paths, ensure_audit_subdirs, sanitize_package_name


@dataclass(frozen=True)
class DownloadPlan:
    package_name: str
    paths: AuditPaths
    program: str
    arguments: list[str]


def git_path() -> str | None:
    return shutil.which("git")


def ensure_git_available() -> str:
    path = git_path()
    if not path:
        raise FileNotFoundError(
            "git nao encontrado. Instale git para clonar o repositório AUR do pacote."
        )
    return path


def create_download_plan(package_name: str, base_dir: Path | None = None) -> DownloadPlan:
    safe_name = sanitize_package_name(package_name)
    program = ensure_git_available()
    paths = create_audit_paths(safe_name, base_dir=base_dir)
    return DownloadPlan(
        package_name=safe_name,
        paths=paths,
        program=program,
        arguments=["clone", f"https://aur.archlinux.org/{safe_name}.git", str(paths.package_dir)],
    )


def resolve_downloaded_package_dir(plan: DownloadPlan) -> Path:
    if plan.paths.package_dir.exists():
        ensure_audit_subdirs(plan.paths)
        return plan.paths.package_dir
    reserved = {
        "aur-repo",
        "sources",
        "srcdir",
        "pkgdir",
        "build",
        "packages",
        "logs",
        "reports",
        "hashes",
        "gnupg",
    }
    candidates = [
        path
        for path in plan.paths.session_dir.iterdir()
        if path.is_dir() and path.name not in reserved
    ]
    if len(candidates) == 1:
        candidates[0].rename(plan.paths.package_dir)
        ensure_audit_subdirs(plan.paths)
        return plan.paths.package_dir
    raise FileNotFoundError(
        f"Download terminou, mas a pasta do pacote nao foi encontrada em {plan.paths.session_dir}"
    )
