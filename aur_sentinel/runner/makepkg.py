from __future__ import annotations

from pathlib import Path

from aur_sentinel.utils.paths import AuditPaths


def verifysource_args() -> list[str]:
    return ["--verifysource", "--nodeps"]


def extract_sources_args() -> list[str]:
    return ["-o", "--noprepare", "--nodeps"]


def audit_environment(paths: AuditPaths) -> dict[str, str]:
    return {
        "SRCDEST": str(paths.sources_dir),
        "BUILDDIR": str(paths.build_dir),
        "PKGDEST": str(paths.packages_dir),
        "LOGDEST": str(paths.logs_dir),
        "GNUPGHOME": str(paths.gnupg_dir),
    }


def candidate_src_roots(paths: AuditPaths, package_dir: Path) -> list[Path]:
    candidates = [
        package_dir / "src",
        paths.srcdir,
        paths.build_dir,
    ]
    results: list[Path] = []
    for candidate in candidates:
        if candidate.exists() and candidate.is_dir() and candidate not in results:
            results.append(candidate)
    return results
