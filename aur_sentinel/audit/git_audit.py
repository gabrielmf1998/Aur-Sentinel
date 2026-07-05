from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .models import Finding, GitAuditResult


GIT_TIMEOUT_SECONDS = 20
AUDITED_GIT_PATHS = {"PKGBUILD", ".SRCINFO"}


def _run_git(package_dir: Path, args: list[str]) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=package_dir,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)
    return completed.returncode, completed.stdout


def audit_git(package_dir: Path) -> tuple[GitAuditResult, list[Finding]]:
    findings: list[Finding] = []
    if shutil.which("git") is None:
        result = GitAuditResult(available=False, error="git nao encontrado no PATH")
        findings.append(
            Finding(
                id="info.git-missing",
                name="Git indisponivel",
                severity="INFO",
                file_path=".",
                line=None,
                snippet="git command not found",
                description="A auditoria de historico Git nao pode ser executada.",
                recommendation="Instale git para revisar historico e diffs recentes.",
                source="git",
            )
        )
        return result, findings

    if not (package_dir / ".git").exists():
        return (
            GitAuditResult(available=False, error="repositorio .git nao encontrado"),
            [
                Finding(
                    id="info.git-metadata-missing",
                    name="Metadados Git ausentes",
                    severity="INFO",
                    file_path=".",
                    line=None,
                    snippet=".git ausente",
                    description="Nao foi possivel auditar historico Git local.",
                    recommendation="Confirme se o download manteve o repositorio AUR completo.",
                    source="git",
                )
            ],
        )

    _, log_oneline = _run_git(package_dir, ["log", "--oneline", "--decorate", "-n", "20"])
    _, show_stat = _run_git(package_dir, ["show", "--stat", "--oneline", "HEAD"])
    diff_code, recent_diff = _run_git(
        package_dir,
        ["diff", "HEAD~1..HEAD", "--", "PKGBUILD", ".SRCINFO", "*.install"],
    )
    if diff_code != 0 and "bad revision" in recent_diff.lower():
        recent_diff = "Sem commit anterior disponivel para diff HEAD~1..HEAD.\n" + recent_diff

    _, last_commit = _run_git(package_dir, ["log", "-1", "--format=%H"])
    _, last_date = _run_git(package_dir, ["log", "-1", "--format=%cI"])
    _, last_author = _run_git(package_dir, ["log", "-1", "--format=%an <%ae>"])
    _, changed_files_output = _run_git(
        package_dir,
        ["diff-tree", "--no-commit-id", "--name-status", "-r", "HEAD"],
    )
    _, recent_sensitive_output = _run_git(
        package_dir,
        [
            "log",
            "--name-status",
            "--format=",
            "--no-renames",
            "-n",
            "20",
            "--",
            "PKGBUILD",
            ".SRCINFO",
            "*.install",
        ],
    )

    changed_files: list[str] = []
    protected_changed: list[str] = []
    new_install_files: list[str] = []
    for raw_line in changed_files_output.splitlines():
        parts = raw_line.split(maxsplit=1)
        if not parts:
            continue
        status = parts[0]
        filename = parts[1] if len(parts) > 1 else ""
        changed_files.append(raw_line)
        plain_name = Path(filename).name
        if filename in AUDITED_GIT_PATHS or plain_name.endswith(".install"):
            protected_changed.append(filename)
        if status.startswith("A") and plain_name.endswith(".install"):
            new_install_files.append(filename)

    for raw_line in recent_sensitive_output.splitlines():
        parts = raw_line.split(maxsplit=1)
        if len(parts) < 2:
            continue
        status, filename = parts
        plain_name = Path(filename).name
        if filename in AUDITED_GIT_PATHS or plain_name.endswith(".install"):
            protected_changed.append(filename)
        if status.startswith("A") and plain_name.endswith(".install"):
            new_install_files.append(filename)

    for filename in sorted(set(protected_changed)):
        findings.append(
            Finding(
                id="medium.git-sensitive-file-changed",
                name="Arquivo auditavel alterado recentemente",
                classification="OBSERVATION",
                severity="INFO",
                status_impact="NONE",
                file_path=filename,
                line=None,
                snippet=filename,
                description="PKGBUILD, .SRCINFO ou scriptlet .install mudou no commit recente.",
                recommendation="Observação neutra; revise o diff se quiser contexto.",
                source="git",
            )
        )

    for filename in sorted(set(new_install_files)):
        findings.append(
            Finding(
                id="high.git-new-install-scriptlet",
                name="Novo scriptlet .install no historico recente",
                classification="OBSERVATION",
                severity="INFO",
                status_impact="NONE",
                file_path=filename,
                line=None,
                snippet=filename,
                description="Um arquivo .install novo apareceu no commit mais recente.",
                recommendation="Observação neutra; o conteúdo do scriptlet define se há suspeita ou criticidade.",
                source="git",
            )
        )

    result = GitAuditResult(
        available=True,
        last_commit=last_commit.strip(),
        last_commit_date=last_date.strip(),
        last_commit_author=last_author.strip(),
        changed_files=changed_files,
        log_oneline=log_oneline.strip(),
        show_stat=show_stat.strip(),
        recent_diff=recent_diff.strip(),
    )
    return result, findings
