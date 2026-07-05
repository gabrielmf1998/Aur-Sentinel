from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from .timefmt import timestamp_for_path


SAFE_PACKAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._+-]{0,254}$")


@dataclass(frozen=True)
class AuditPaths:
    base_dir: Path
    session_dir: Path
    package_dir: Path
    sources_dir: Path
    srcdir: Path
    pkgdir: Path
    build_dir: Path
    packages_dir: Path
    logs_dir: Path
    reports_dir: Path
    hashes_dir: Path
    gnupg_dir: Path


def downloads_dir() -> Path:
    xdg_download = os.environ.get("XDG_DOWNLOAD_DIR")
    if xdg_download:
        return Path(xdg_download).expanduser()
    return Path.home() / "Downloads"


def audit_base_dir() -> Path:
    return downloads_dir() / "AUR-Audit"


def sanitize_package_name(package_name: str) -> str:
    package_name = package_name.strip()
    if not SAFE_PACKAGE_RE.match(package_name):
        raise ValueError(
            "Nome de pacote invalido. Use apenas letras, numeros, @, ponto, _, + e -; "
            "nao comece com ponto ou hifen."
        )
    if package_name.startswith((".", "-")):
        raise ValueError("Nome de pacote nao pode comecar com ponto ou hifen.")
    return package_name


def create_audit_paths(package_name: str, base_dir: Path | None = None) -> AuditPaths:
    safe_name = sanitize_package_name(package_name)
    root = base_dir or audit_base_dir()
    session_dir = root / safe_name / timestamp_for_path()
    if session_dir.exists():
        raise FileExistsError(f"Diretorio de auditoria ja existe: {session_dir}")
    session_dir.mkdir(parents=True, exist_ok=False)
    return AuditPaths(
        base_dir=root,
        session_dir=session_dir,
        package_dir=session_dir / "aur-repo",
        sources_dir=session_dir / "sources",
        srcdir=session_dir / "srcdir",
        pkgdir=session_dir / "pkgdir",
        build_dir=session_dir / "build",
        packages_dir=session_dir / "packages",
        logs_dir=session_dir / "logs",
        reports_dir=session_dir / "reports",
        hashes_dir=session_dir / "hashes",
        gnupg_dir=session_dir / "gnupg",
    )


def ensure_audit_subdirs(paths: AuditPaths) -> None:
    for path in (
        paths.sources_dir,
        paths.srcdir,
        paths.pkgdir,
        paths.build_dir,
        paths.packages_dir,
        paths.logs_dir,
        paths.reports_dir,
        paths.hashes_dir,
        paths.gnupg_dir,
    ):
        path.mkdir(parents=True, exist_ok=True)
