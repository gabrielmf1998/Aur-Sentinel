from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from .binary_analyzer import BinaryInfo, analyze_binary
from .file_audit import is_probably_binary, safe_read_text, strip_inline_comment
from .models import Finding
from .scan_limits import MAX_FILES_SCANNED, MAX_REGEX_FILE_BYTES, MAX_TEXT_FILE_BYTES


INSTALLER_NAMES = {
    ".INSTALL",
    "install",
    "install.sh",
    "installer.sh",
    "setup.sh",
    "postinstall",
    "post_install",
    "preinstall",
    "pre_install",
    "post_upgrade",
    "pre_upgrade",
    "post_remove",
    "pre_remove",
    "configure",
    "autogen.sh",
    "bootstrap.sh",
}

LOCKFILE_NAMES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lockb",
    "bun.lock",
    "Cargo.lock",
    "go.sum",
    "poetry.lock",
    "Pipfile.lock",
    "Gemfile.lock",
    "composer.lock",
}

REMOTE_EXEC_RE = re.compile(
    r"\bcurl\s+.*\|\s*(?:bash|sh)\b|"
    r"\bwget\s+.*\|\s*(?:bash|sh)\b|"
    r"\bbash\s+<\(\s*curl\b|"
    r"\bsh\s+<\(\s*wget\b|"
    r"\beval\s+.*(?:curl|wget)\b",
    re.IGNORECASE,
)
MALICIOUS_DEP_RE = re.compile(r"\b(?:atomic-lockfile|js-digest|lockfile-js)\b", re.IGNORECASE)
INSTALL_DEP_MANAGER_RE = re.compile(
    r"\b(?:npm\s+(?:install|i)|bun\s+install|pnpm\s+install|yarn\s+install|npx\b|"
    r"bunx\b|pnpm\s+dlx|yarn\s+dlx|pip\s+install|python\s+-m\s+pip\s+install|"
    r"cargo\s+install|go\s+install\s+.*@latest)\b",
    re.IGNORECASE,
)
PERSISTENCE_RE = re.compile(
    r"\bsystemctl\s+(?:enable|start)(?:\s+--now)?\b|crontab\b|\.config/systemd/user|"
    r"/etc/systemd/system|/etc/cron|xdg/autostart|"
    r"(?:>>?|tee\s+-a|sed\s+-i|printf\b|echo\b).*(?:\.bashrc|\.zshrc|\.profile|config\.fish)",
    re.IGNORECASE,
)
EXFIL_ACTION_RE = re.compile(
    r"\bcurl\s+.*(?:-F|--form|--data|-d)\b|\bwget\s+.*--post-data\b|"
    r"\bnc\b|\bncat\b|\bsocat\b|/dev/tcp|\bscp\b|\brsync\b",
    re.IGNORECASE,
)
SENSITIVE_DATA_RE = re.compile(
    r"\.ssh|\.gnupg|\.aws|\.kube|\.docker|\.npmrc|_authToken|token|secret|"
    r"password|cookie|Login Data|Vault|github|discord|slack|telegram",
    re.IGNORECASE,
)
OBFUSCATION_EXEC_RE = re.compile(
    r"\bbase64\s+-d.*\|\s*(?:bash|sh)\b|"
    r"\bxxd\s+-r.*\|\s*(?:bash|sh)\b|"
    r"\bopenssl\s+enc.*\|\s*(?:bash|sh)\b|"
    r"\beval\b|\bbash\s+-c\b|\bsh\s+-c\b|\bpython\s+-c\b|\bperl\s+-e\b|"
    r"\bruby\s+-e\b|\bnode\s+-e\b",
    re.IGNORECASE,
)
SYSTEM_CHANGE_RE = re.compile(
    r"\bpacman-key\b|/etc/pacman\.conf|/etc/pacman\.d/mirrorlist|\bmkinitcpio\b|"
    r"\bdracut\b|\bgrub-install\b|\bgrub-mkconfig\b|\bbootctl\b|\befibootmgr\b|"
    r"\bmodprobe\b|\binsmod\b|\bdkms\b|/etc/ld\.so\.preload|\bLD_PRELOAD\b",
    re.IGNORECASE,
)
PERMISSIONS_RE = re.compile(r"\bchmod\s+4755\b|\bchmod\s+u\+s\b|\bsetcap\b|\bchown\s+root\b", re.IGNORECASE)
DESTRUCTIVE_RE = re.compile(
    r"\brm\s+-rf\s+(?:/|\$HOME|~/)|\bfind\s+/.*-delete\b|\bdd\s+if=/dev/zero\b|"
    r"\bmkfs\.|\bwipefs\b|\bshred\b",
    re.IGNORECASE,
)
NORMAL_BUILD_RE = re.compile(
    r"\b(?:npm\s+run\s+build|pnpm\s+build|pnpm\s+run\s+build|cargo\s+build|go\s+build|"
    r"python(?:3)?\s+-m\s+build|cmake\b|make\b|meson\b|ninja\b|electron\b|AppImage\b)",
    re.IGNORECASE,
)


@dataclass
class ScannedFile:
    path: str
    kind: str
    size: int
    findings: int = 0
    max_severity: str = "INFO"
    skipped_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "kind": self.kind,
            "size": self.size,
            "findings": self.findings,
            "max_severity": self.max_severity,
            "skipped_reason": self.skipped_reason,
        }


@dataclass
class SourceTreeReport:
    root: str
    files_scanned: int = 0
    files_skipped: int = 0
    scripts_found: int = 0
    binaries_found: int = 0
    package_managers_detected: list[str] = field(default_factory=list)
    lockfiles_detected: list[str] = field(default_factory=list)
    scanned_files: list[ScannedFile] = field(default_factory=list)
    binaries: list[BinaryInfo] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    partial: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, Any]:
        return {
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "scripts_found": self.scripts_found,
            "binaries_found": self.binaries_found,
            "package_managers_detected": sorted(set(self.package_managers_detected)),
            "lockfiles_detected": sorted(set(self.lockfiles_detected)),
            "partial": self.partial,
        }

    def to_dict(self) -> dict[str, Any]:
        data = self.summary
        data["root"] = self.root
        data["files"] = [item.to_dict() for item in self.scanned_files]
        data["binaries"] = [item.to_dict() for item in self.binaries]
        data["findings"] = [item.to_dict() for item in self.findings]
        data["errors"] = self.errors[-100:]
        return data


def scan_source_tree(srcdir: Path, known_indicators: list[str] | None = None) -> SourceTreeReport:
    known_indicators = known_indicators or ["atomic-lockfile", "js-digest", "lockfile-js"]
    report = SourceTreeReport(root=str(srcdir))
    if not srcdir.exists():
        report.partial = True
        report.errors.append(f"Source tree não existe: {srcdir}")
        return report

    for path in _iter_source_files(srcdir, report):
        if report.files_scanned >= MAX_FILES_SCANNED:
            report.partial = True
            report.files_skipped += 1
            break
        try:
            stat = path.stat()
        except OSError as exc:
            report.files_skipped += 1
            report.errors.append(f"{path}: {exc}")
            continue

        rel = path.relative_to(srcdir).as_posix()
        kind = classify_source_tree_file(path)
        scanned = ScannedFile(path=rel, kind=kind, size=stat.st_size)
        report.files_scanned += 1
        if _is_scriptish(kind):
            report.scripts_found += 1
        if path.name in LOCKFILE_NAMES:
            report.lockfiles_detected.append(path.name)

        try:
            binary_info, binary_findings = analyze_binary(path, srcdir)
        except Exception as exc:
            binary_info, binary_findings = None, []
            report.errors.append(f"Falha analisando binário {rel}: {exc}")
        if binary_info:
            report.binaries_found += 1
            report.binaries.append(binary_info)
            _extend_file_findings(report, scanned, binary_findings)
            report.scanned_files.append(scanned)
            continue
        binary_like = is_probably_binary(path)
        if binary_like:
            scanned.kind = "binary_data"
            report.scanned_files.append(scanned)
            continue

        if stat.st_size > MAX_REGEX_FILE_BYTES:
            scanned.skipped_reason = "Arquivo grande. Análise textual parcial/ignorada por limite."
            report.files_skipped += 1
            report.partial = True
            report.scanned_files.append(scanned)
            continue

        if not binary_like:
            text, truncated = safe_read_text(path, max_bytes=min(MAX_TEXT_FILE_BYTES, MAX_REGEX_FILE_BYTES))
            if truncated:
                report.partial = True
                scanned.skipped_reason = "Arquivo textual truncado por limite."
                _extend_file_findings(
                    report,
                    scanned,
                    [
                        Finding(
                            rule_id="SOURCE_TREE_TEXT_TRUNCATED",
                            name="ANÁLISE PARCIAL: arquivo textual truncado",
                            classification="CONCRETE_SUSPICION",
                            severity="REVIEW",
                            status_impact="YELLOW",
                            category="source_tree",
                            file_path=rel,
                            matched_text=scanned.skipped_reason,
                            behavior="Arquivo textual excedeu limite de leitura.",
                            why_it_matters="Análise parcial não deve gerar status verde automaticamente.",
                            evidence=f"{stat.st_size} bytes",
                            recommendation="Revise manualmente ou aumente limites em ambiente isolado.",
                            source="source_tree",
                        )
                    ],
                )
            file_findings = _scan_text_file(rel, kind, text, known_indicators)
            _extend_file_findings(report, scanned, file_findings)
            _update_package_manager_summary(path, text, report)
        report.scanned_files.append(scanned)

    if report.partial:
        report.findings.append(
            Finding(
                rule_id="SOURCE_TREE_ANALYSIS_PARTIAL",
                name="ANÁLISE PARCIAL: limite atingido",
                classification="CONCRETE_SUSPICION",
                severity="REVIEW",
                status_impact="YELLOW",
                category="source_tree",
                file_path=str(srcdir),
                matched_text="ANÁLISE PARCIAL: limite atingido",
                behavior="A análise de sources ficou incompleta por limite ou erro controlado.",
                why_it_matters="Status verde exige auditoria suficiente; análise parcial precisa de revisão.",
                evidence=f"files_scanned={report.files_scanned}, skipped={report.files_skipped}",
                recommendation="Revise manualmente os arquivos ignorados ou reexecute com limites maiores.",
                source="source_tree",
            )
        )
    return report


def classify_source_tree_file(path: Path) -> str:
    name = path.name
    lower_name = name.lower()
    suffix = path.suffix.lower()
    rel_parts = {part.lower() for part in path.parts}
    if name.endswith(".install") or name in INSTALLER_NAMES or lower_name in {item.lower() for item in INSTALLER_NAMES}:
        return "installer"
    if "debian" in rel_parts and lower_name in {"postinst", "preinst", "prerm", "postrm"}:
        return "installer"
    if suffix in {".sh", ".bash", ".zsh", ".fish"} or _has_shell_shebang(path):
        return "shell"
    if suffix in {".hook"}:
        return "hook"
    if suffix in {".service", ".timer", ".socket", ".path"}:
        return "systemd"
    if suffix == ".desktop" or "autostart" in rel_parts:
        return "desktop"
    if name == "package.json":
        return "node_package"
    if name in LOCKFILE_NAMES:
        return "lockfile"
    if name in {"setup.py", "pyproject.toml", "setup.cfg", "requirements.txt", "Pipfile", "Pipfile.lock", "poetry.lock"}:
        return "python"
    if name in {"Cargo.toml", "Cargo.lock", "build.rs"}:
        return "rust"
    if name == "go.mod" or name == "go.sum" or suffix == ".go":
        return "go"
    if name in {"pom.xml"}:
        return "java_maven"
    if name in {"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "gradlew"}:
        return "java_gradle"
    if name == "Makefile":
        return "make"
    if name == "CMakeLists.txt":
        return "cmake"
    if name == "configure":
        return "configure"
    if suffix in {".pacman"} or ".pkg.tar." in lower_name:
        return "package_archive"
    return "text"


def _iter_source_files(root: Path, report: SourceTreeReport) -> Iterator[Path]:
    excluded = {".git", "__pycache__", ".venv", "venv", "node_modules", ".gradle", "target"}
    for current_root, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [name for name in dirnames if name not in excluded]
        for dirname in list(dirnames):
            path = Path(current_root) / dirname
            if path.is_symlink():
                dirnames.remove(dirname)
                report.files_skipped += 1
        for filename in sorted(filenames):
            path = Path(current_root) / filename
            if path.is_symlink():
                report.files_skipped += 1
                continue
            if path.is_file():
                yield path


def _has_shell_shebang(path: Path) -> bool:
    try:
        first = path.open("rb").readline(160).decode("utf-8", errors="ignore")
    except OSError:
        return False
    return first.startswith(("#!/bin/sh", "#!/bin/bash", "#!/usr/bin/env bash", "#!/usr/bin/env sh"))


def _scan_text_file(rel: str, kind: str, text: str, known_indicators: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()
    for index, raw_line in enumerate(lines, start=1):
        stripped, comment = strip_inline_comment(raw_line)
        if not stripped.strip():
            continue
        stripped = stripped.strip()

        for rule_id, pattern, behavior, why in (
            ("SOURCE_TREE_REMOTE_EXECUTION", REMOTE_EXEC_RE, "Execução remota direta.", "curl/wget pipe shell é padrão documentado de falha AUR."),
            ("SOURCE_TREE_MALICIOUS_DEPENDENCY", MALICIOUS_DEP_RE, "IOC/dependência maliciosa conhecida.", "Indicador associado a campanha documentada."),
            ("SOURCE_TREE_PERSISTENCE", PERSISTENCE_RE, "Persistência automática.", "Ativa serviço, cron, autostart ou altera shell profile."),
            ("SOURCE_TREE_OBFUSCATION_EXECUTION", OBFUSCATION_EXEC_RE, "Ofuscação ou execução dinâmica.", "Execução dinâmica/ofuscada dificulta auditoria e pode reconstruir payload."),
            ("SOURCE_TREE_SYSTEM_CHANGE", SYSTEM_CHANGE_RE, "Alteração sensível de sistema.", "Afeta boot, pacman, kernel, preload ou configuração crítica."),
            ("SOURCE_TREE_DANGEROUS_PERMISSIONS", PERMISSIONS_RE, "Permissão privilegiada.", "SUID/capability/propriedade root ampliam impacto."),
            ("SOURCE_TREE_DESTRUCTIVE_COMMAND", DESTRUCTIVE_RE, "Comando destrutivo.", "Pode apagar dados ou danificar sistema de arquivos."),
        ):
            match = pattern.search(stripped)
            if match:
                findings.append(_finding(rule_id, "CONCRETE_FAILURE", "CRITICAL", "RED", rel, index, match.group(0), behavior, why))

        if kind == "installer":
            match = INSTALL_DEP_MANAGER_RE.search(stripped)
            if match:
                findings.append(
                    _finding(
                        "SOURCE_TREE_INSTALLER_DEPENDENCY_MANAGER",
                        "CONCRETE_FAILURE",
                        "CRITICAL",
                        "RED",
                        rel,
                        index,
                        match.group(0),
                        "Dependency manager em instalador/scriptlet.",
                        "Instalação dinâmica durante install/postinst é comportamento crítico.",
                    )
                )

        if EXFIL_ACTION_RE.search(stripped) and SENSITIVE_DATA_RE.search(stripped):
            match = EXFIL_ACTION_RE.search(stripped)
            assert match is not None
            findings.append(
                _finding(
                    "SOURCE_TREE_EXFILTRATION",
                    "CONCRETE_FAILURE",
                    "CRITICAL",
                    "RED",
                    rel,
                    index,
                    match.group(0),
                    "Possível exfiltração.",
                    "Comando de rede combinado com caminho/termo sensível.",
                )
            )

        normal = NORMAL_BUILD_RE.search(stripped)
        if normal:
            findings.append(
                _finding(
                    "SOURCE_TREE_NORMAL_BUILD_TOOL",
                    "OBSERVATION",
                    "INFO",
                    "NONE",
                    rel,
                    index,
                    normal.group(0),
                    "Ferramenta de build comum observada.",
                    "Build tools normais não são red flag isolada.",
                )
            )

        for indicator in known_indicators:
            if re.search(rf"(?<![A-Za-z0-9_]){re.escape(indicator)}(?![A-Za-z0-9_])", stripped, re.IGNORECASE):
                findings.append(
                    _finding(
                        "SOURCE_TREE_KNOWN_INDICATOR",
                        "CONCRETE_FAILURE",
                        "CRITICAL",
                        "RED",
                        rel,
                        index,
                        indicator,
                        "Indicador conhecido encontrado nos sources extraídos.",
                        "Indicador associado a campanha documentada.",
                        related_incident_id="aur_2026_atomic_arch",
                        related_incident_year=2026,
                        related_incident_name="AUR 2026 Atomic Arch npm/Bun dependency campaign",
                        references=[
                            "https://archlinux.org/news/active-aur-malicious-packages-incident/",
                            "https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency",
                        ],
                    )
                )
        if comment and any(indicator.lower() in comment.lower() for indicator in known_indicators):
            findings.append(
                _finding(
                    "SOURCE_TREE_KNOWN_INDICATOR_COMMENT",
                    "INFO",
                    "INFO",
                    "NONE",
                    rel,
                    index,
                    comment.strip()[:120],
                    "Indicador conhecido citado em comentário.",
                    "Comentário não é execução.",
                )
            )

    if kind == "node_package":
        findings.extend(_scan_package_json(rel, text))
    elif kind == "rust" and rel.endswith("build.rs"):
        findings.extend(_scan_observation_lines(rel, text, re.compile(r"Command::new|curl|wget|git|ssh|https?://|HOME|\.ssh|include_bytes!", re.I), "SOURCE_TREE_BUILD_RS_OBSERVATION", "build.rs contém chamada sensível observada."))
    elif kind == "go":
        findings.extend(_scan_observation_lines(rel, text, re.compile(r"//go:generate|\bgo\s+generate\b|\bgo\s+install\s+.*@latest|\bgo\s+get\b", re.I), "SOURCE_TREE_GO_OBSERVATION", "Arquivo Go contém diretiva/comando sensível observado."))
    elif kind == "python":
        findings.extend(_scan_observation_lines(rel, text, re.compile(r"cmdclass|os\.system|subprocess|eval|exec|requests|urllib|pip\s+install\s+(?:git\+https://|https://)|git\+https://", re.I), "SOURCE_TREE_PYTHON_OBSERVATION", "Empacotamento Python contém chamada sensível observada."))
    elif kind == "java_gradle":
        findings.extend(_scan_observation_lines(rel, text, re.compile(r"\bexec\b|curl|wget|ProcessBuilder|Runtime\.getRuntime|mvn\s+dependency:get|distributionUrl=", re.I), "SOURCE_TREE_GRADLE_OBSERVATION", "Gradle/Maven contém chamada sensível observada."))
    return findings


def _scan_package_json(rel: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        package = json.loads(text)
    except json.JSONDecodeError:
        return findings
    scripts = package.get("scripts", {})
    if isinstance(scripts, dict):
        for name, command in scripts.items():
            command_text = str(command)
            line = _line_number_for_text(text, f'"{name}"')
            remote = REMOTE_EXEC_RE.search(command_text)
            findings.append(
                _finding(
                    "NODE_LIFECYCLE_SCRIPT_REMOTE_EXECUTION" if remote else "NODE_LIFECYCLE_SCRIPT",
                    "CONCRETE_FAILURE" if remote else "OBSERVATION",
                    "CRITICAL" if remote else "INFO",
                    "RED" if remote else "NONE",
                    rel,
                    line,
                    f"{name}: {command_text}",
                    "Lifecycle npm executa conteúdo remoto." if remote else "package.json contém lifecycle script.",
                    "Execução remota em lifecycle é crítica." if remote else "Lifecycle script é observação sem payload concreto.",
                )
            )
    for group in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = package.get(group, {})
        if isinstance(deps, dict):
            for dep in deps:
                if dep in {"atomic-lockfile", "js-digest", "lockfile-js"}:
                    findings.append(
                        _finding(
                            "SOURCE_TREE_KNOWN_INDICATOR",
                            "CONCRETE_FAILURE",
                            "CRITICAL",
                            "RED",
                            rel,
                            _line_number_for_text(text, dep),
                            dep,
                            "Dependência conhecida de campanha em package.json.",
                            "Dependência associada a campanha Atomic Arch.",
                            related_incident_id="aur_2026_atomic_arch",
                            related_incident_year=2026,
                            related_incident_name="AUR 2026 Atomic Arch npm/Bun dependency campaign",
                            references=[
                                "https://archlinux.org/news/active-aur-malicious-packages-incident/",
                                "https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency",
                            ],
                        )
                    )
    return findings


def _scan_observation_lines(
    rel: str,
    text: str,
    pattern: re.Pattern[str],
    rule_id: str,
    behavior: str,
) -> list[Finding]:
    findings: list[Finding] = []
    for index, line in enumerate(text.splitlines(), start=1):
        stripped, _ = strip_inline_comment(line)
        match = pattern.search(stripped)
        if match:
            findings.append(
                _finding(
                    rule_id,
                    "OBSERVATION",
                    "INFO",
                    "NONE",
                    rel,
                    index,
                    match.group(0),
                    behavior,
                    "Achado registrado para revisão contextual; não altera status isoladamente.",
                )
            )
    return findings


def _finding(
    rule_id: str,
    classification: str,
    severity: str,
    status_impact: str,
    rel: str,
    line: int | None,
    matched: str,
    behavior: str,
    why_it_matters: str,
    related_incident_id: str | None = None,
    related_incident_year: int | None = None,
    related_incident_name: str | None = None,
    references: list[str] | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        name="Source tree scan",
        classification=classification,
        severity=severity,
        status_impact=status_impact,
        category="source_tree",
        file_path=rel,
        line_start=line,
        matched_text=matched[:300],
        command=matched[:120],
        behavior=behavior,
        why_it_matters=why_it_matters,
        evidence=matched[:300],
        related_incident_id=related_incident_id,
        related_incident_year=related_incident_year,
        related_incident_name=related_incident_name,
        references=references or [],
        description=behavior,
        risk_explanation=why_it_matters,
        recommendation=(
            "Revisar manualmente e usar IA/especialista antes de instalar."
            if status_impact == "RED"
            else "Revise o arquivo no srcdir se desejar mais contexto."
        ),
        source="source_tree",
    )


def _extend_file_findings(report: SourceTreeReport, scanned: ScannedFile, findings: list[Finding]) -> None:
    report.findings.extend(findings)
    scanned.findings += len(findings)
    scanned.max_severity = _max_severity(scanned.max_severity, [item.severity for item in findings])


def _is_scriptish(kind: str) -> bool:
    return kind in {
        "installer",
        "shell",
        "hook",
        "systemd",
        "desktop",
        "python",
        "rust",
        "go",
        "java_gradle",
        "java_maven",
        "make",
        "cmake",
        "configure",
        "node_package",
    }


def _line_number_for_text(text: str, needle: str) -> int | None:
    for index, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return index
    return None


def _update_package_manager_summary(path: Path, text: str, report: SourceTreeReport) -> None:
    name = path.name
    if name == "package.json":
        report.package_managers_detected.append("npm/node")
    if name == "pnpm-lock.yaml":
        report.package_managers_detected.append("pnpm")
    if name in {"bun.lockb", "bun.lock"}:
        report.package_managers_detected.append("bun")
    if name in {"Cargo.toml", "Cargo.lock", "build.rs"}:
        report.package_managers_detected.append("cargo")
    if name in {"go.mod", "go.sum"}:
        report.package_managers_detected.append("go")
    if name in {"pyproject.toml", "requirements.txt", "poetry.lock", "Pipfile.lock"}:
        report.package_managers_detected.append("python")
    if name in {"pom.xml", "build.gradle", "build.gradle.kts", "gradlew"}:
        report.package_managers_detected.append("java")


def _max_severity(current: str, severities: list[str]) -> str:
    order = {"INFO": 0, "LOW": 1, "OBSERVATION": 1, "REVIEW": 2, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    best = current
    for severity in severities:
        if order.get(severity, 0) > order.get(best, 0):
            best = severity
    return best
