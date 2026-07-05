from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Iterable

from aur_sentinel.utils.timefmt import format_unix_timestamp, now_local_string

from .archive_analyzer import analyze_archives
from .command_knowledge import category_for_rule, explain_text
from .file_audit import (
    classify_file,
    compare_hashes,
    hash_files,
    iter_text_files,
    parse_pkgbuild_assignments,
    parse_srcinfo,
    safe_read_text,
    strip_inline_comment,
    write_hash_file,
)
from .git_audit import audit_git
from .incident_patterns import configured_indicator_matches, match_known_incident_patterns
from .models import Finding, AuditReport, Rule
from .rules import (
    DANGEROUS_NPM_SCRIPT_RE,
    NPM_LIFECYCLE_SCRIPTS,
    SENSITIVE_DEPENDENCIES,
    STATIC_RULES,
)
from .source_integrity import parse_source_integrity


LOCKFILES_BY_TOOL = {
    "npm": ("package-lock.json", "npm-shrinkwrap.json"),
    "pnpm": ("pnpm-lock.yaml",),
    "yarn": ("yarn.lock",),
    "bun": ("bun.lockb", "bun.lock"),
    "cargo": ("Cargo.lock",),
    "go": ("go.sum",),
    "poetry": ("poetry.lock",),
    "pip": ("requirements.txt", "requirements.lock", "poetry.lock", "Pipfile.lock"),
    "pipenv": ("Pipfile.lock",),
    "ruby": ("Gemfile.lock",),
    "composer": ("composer.lock",),
}


PACKAGE_WRITE_OUTSIDE_RE = re.compile(
    r"(?:\b(?:install|cp|mv|mkdir|ln|tee|sed)\b[^#\n]*(?:\s|=)/(?:usr|etc|var|opt|boot|root|home)\b|"
    r">\s*/(?:usr|etc|var|opt|boot|root|home)\b)"
)

FUNCTION_START_RE = re.compile(
    r"^\s*(?:function\s+)?(?P<name>prepare|build|check|package(?:_[A-Za-z0-9@._+-]+)?)\s*(?:\(\))?\s*\{"
)

PROTECTED_COMPARE_KEYS = {
    "pkgname",
    "pkgbase",
    "pkgver",
    "pkgrel",
    "epoch",
    "source",
    "depends",
    "makedepends",
    "license",
    "install",
}

PKGBUILD_DECLARATIVE_KEYS = {
    "pkgbase",
    "pkgname",
    "pkgver",
    "pkgrel",
    "epoch",
    "pkgdesc",
    "arch",
    "url",
    "license",
    "groups",
    "depends",
    "makedepends",
    "checkdepends",
    "optdepends",
    "provides",
    "conflicts",
    "replaces",
    "backup",
    "options",
    "install",
    "changelog",
    "source",
    "noextract",
    "validpgpkeys",
    "md5sums",
    "sha1sums",
    "sha256sums",
    "sha512sums",
    "b2sums",
}

RULES_ALLOWED_IN_DECLARATIVE_KEYS = {
    "medium.skipped-or-weak-checksum",
    "medium.install-directive",
}

NODE_INSTALL_RE = re.compile(
    r"\b(?:npm\s+(?:install|i)\b|bun\s+install\b|pnpm\s+install\b|"
    r"yarn\s+install\b|npx\b|bunx\b)",
    re.IGNORECASE,
)

NORMAL_BUILD_TOOL_RE = re.compile(
    r"\b(?:npm\s+run\s+build|pnpm\s+build|pnpm\s+run\s+build|cargo\s+build|go\s+build|"
    r"python(?:3)?\s+-m\s+build|cmake\b|make\b|meson\b|ninja\b|electron\b|AppImage\b)",
    re.IGNORECASE,
)

INSTALL_SCRIPT_DEP_MANAGER_RE = re.compile(
    r"\b(?:npm\s+(?:install|i)|bun\s+install|pnpm\s+install|yarn\s+install|npx\b|"
    r"bunx\b|pnpm\s+dlx\b|yarn\s+dlx\b|pip\s+install|python\s+-m\s+pip\s+install|"
    r"cargo\s+install|go\s+install\s+.*@latest)\b",
    re.IGNORECASE,
)

INSTALL_SCRIPT_PERSISTENCE_RE = re.compile(
    r"\bsystemctl\s+(?:enable|start)(?:\s+--now)?\b|crontab\b|\.config/systemd/user|"
    r"/etc/systemd/system|/etc/cron|xdg/autostart|"
    r"(?:>>?|tee\s+-a|sed\s+-i|printf\b|echo\b).*(?:\.bashrc|\.zshrc|\.profile|config\.fish)",
    re.IGNORECASE,
)

RECENT_SENSITIVE_ADDITION_RE = re.compile(
    r"^\+.*(?:npm\s+(?:install|i)|bun\s+install|npx\b|bunx\b|pnpm\s+dlx|"
    r"curl\b[^|]*\|\s*bash|wget\b[^|]*\|\s*sh|systemctl\b|base64\s+-d|"
    r"\beval\b|chmod\s+4755|setcap\b|atomic-lockfile|lockfile-js|js-digest|"
    r"\.bashrc|\.zshrc|\.profile|config\.fish)",
    re.IGNORECASE | re.MULTILINE,
)


def _status_marker(status: str) -> str:
    normalized = status.lower()
    if normalized in {"analisado", "verificados", "extraídos/analisados", "analisados", "ok", "não existe", "não encontrados", "não disponível", "não aplicável"}:
        return "OK"
    if normalized in {"falhou", "erro"}:
        return "FALHOU"
    if normalized in {"parcial"}:
        return "ANALISAR"
    return "--"


def _render_evidence_group(findings: list[Finding], empty: str) -> list[str]:
    if not findings:
        return [empty]
    lines: list[str] = []
    for item in findings:
        lines.extend(
            [
                "",
                f"Evidência encontrada: {item.name}",
                f"Arquivo: {item.file_path or '-'}",
                f"Linha: {item.line_start if item.line_start is not None else '-'}",
                f"Trecho: {item.matched_text or '-'}",
                f"Comportamento: {item.behavior}",
                f"Incidente relacionado: {item.related_incident_name or item.incident_name or '-'}",
                f"Explicação: {item.why_it_matters or item.risk_explanation or '-'}",
                f"Recomendação: {item.recommendation or '-'}",
            ]
        )
    return lines


class AuditScanner:
    def __init__(self, rules: Iterable[Rule] | None = None) -> None:
        self.rules = list(rules or STATIC_RULES)
        self._compiled_rules = [
            (rule, re.compile(rule.regex, re.IGNORECASE)) for rule in self.rules
        ]
        self.known_bad_indicators = self._load_known_bad_indicators()

    def scan(
        self,
        package_dir: Path,
        metadata: dict[str, Any] | None = None,
        source_integrity: Any | None = None,
        source_tree: Any | None = None,
        dependency_audit: Any | None = None,
        archive_analysis: Any | None = None,
        audit_phases: dict[str, str] | None = None,
    ) -> AuditReport:
        package_dir = package_dir.resolve()
        metadata = dict(metadata or {})
        package_name = metadata.get("Name") or package_dir.name

        findings: list[Finding] = []
        file_hashes = hash_files(package_dir)
        generated_at = now_local_string()

        for path in iter_text_files(package_dir):
            rel = path.relative_to(package_dir).as_posix()
            text, truncated = safe_read_text(path)
            if truncated:
                findings.append(
                    Finding(
                        id="info.file-truncated",
                        name="Arquivo grande truncado para leitura visual",
                        severity="INFO",
                        file_path=rel,
                        line=None,
                        snippet=f">{2 * 1024 * 1024} bytes",
                        description="O arquivo excede o limite de leitura textual do auditor.",
                        recommendation="Revise esse arquivo manualmente antes de instalar.",
                    )
                )
            findings.extend(self._scan_text_file(rel, text, classify_file(path)))

        findings.extend(self._scan_install_files(package_dir))
        findings.extend(self._scan_pkgbuild_specific(package_dir))
        findings.extend(self._scan_srcinfo_consistency(package_dir))
        findings.extend(self._scan_metadata(metadata))
        findings.extend(self._scan_ecosystem_files(package_dir))
        findings.extend(self._scan_known_bad_indicators(package_dir))
        findings.extend(self._scan_known_incident_patterns(package_dir, str(package_name)))

        git_result, git_findings = audit_git(package_dir)
        findings.extend(git_findings)
        findings.extend(self._scan_recent_sensitive_diff(git_result))

        normalized_metadata = self._normalize_metadata(metadata)
        if source_integrity is None:
            source_integrity = parse_source_integrity(
                package_dir,
                upstream_url=str(normalized_metadata.get("URL") or ""),
            )
        findings.extend(getattr(source_integrity, "findings", []) or [])
        findings.extend(self._scan_neutral_observations(package_dir, str(package_name), normalized_metadata, source_integrity))
        findings.extend(getattr(archive_analysis, "findings", []) or [])
        findings.extend(getattr(source_tree, "findings", []) or [])
        findings.extend(getattr(dependency_audit, "findings", []) or [])

        findings = self._deduplicate(findings)
        findings.extend(self._scan_dependency_manager_lockfiles(package_dir, findings))
        findings = self._deduplicate(findings)
        report = AuditReport(
            package_name=str(package_name),
            package_dir=package_dir,
            generated_at=generated_at,
            metadata=normalized_metadata,
            findings=findings,
            file_hashes=file_hashes,
            git=git_result,
            audit_phases=audit_phases or {"initial_static_audit": "completed"},
            source_integrity=source_integrity,
            source_tree=source_tree,
            dependency_audit=dependency_audit,
            archive_analysis=archive_analysis,
        )
        self.write_outputs(report)
        return report

    def write_outputs(self, report: AuditReport) -> None:
        report.package_dir.mkdir(parents=True, exist_ok=True)
        report_dirs = [report.package_dir]
        sibling_reports = report.package_dir.parent / "reports"
        sibling_hashes = report.package_dir.parent / "hashes"
        if report.package_dir.name == "aur-repo":
            sibling_reports.mkdir(parents=True, exist_ok=True)
            sibling_hashes.mkdir(parents=True, exist_ok=True)
            report_dirs.append(sibling_reports)

        payload = json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n"
        text_report = self.render_text_report(report)
        for output_dir in report_dirs:
            (output_dir / "audit-report.json").write_text(payload, encoding="utf-8")
            (output_dir / "audit-report.txt").write_text(text_report, encoding="utf-8")
        write_hash_file(report.package_dir, report.file_hashes)
        if sibling_hashes.exists():
            write_hash_file(sibling_hashes, report.file_hashes)

    def render_text_report(self, report: AuditReport) -> str:
        verdict = report.final_verdict
        analyzed = report.analysis_status()
        lines = [
            f"RESULTADO: {verdict.label}",
            "",
            "Resumo:",
            verdict.summary,
            "",
            "O que foi analisado:",
            f"[{_status_marker(analyzed['pkgbuild'])}] PKGBUILD: {analyzed['pkgbuild']}",
            f"[{_status_marker(analyzed['srcinfo'])}] .SRCINFO: {analyzed['srcinfo']}",
            f"[{_status_marker(analyzed['install_scripts'])}] *.install: {analyzed['install_scripts']}",
            f"[{_status_marker(analyzed['git_history'])}] Histórico Git: {analyzed['git_history']}",
            f"[{_status_marker(analyzed['sources'])}] Sources: {analyzed['sources']}",
            f"[{_status_marker(analyzed['archives'])}] Arquivos compactados: {analyzed['archives']}",
            f"[{_status_marker(analyzed['scripts'])}] Scripts: {analyzed['scripts']}",
            f"[{_status_marker(analyzed['binaries'])}] Binários: {analyzed['binaries']}",
            f"[{_status_marker(analyzed['checksums'])}] Checksums: {analyzed['checksums']}",
            f"[{_status_marker(analyzed['pgp'])}] PGP: {analyzed['pgp']}",
            "",
            "Falhas críticas:",
        ]
        lines.extend(_render_evidence_group(report.concrete_failures, empty="Nenhuma."))
        lines.extend(["", "Suspeitas concretas:"])
        lines.extend(_render_evidence_group(report.concrete_suspicions, empty="Nenhuma."))
        lines.extend(["", "Observações:"])
        if report.observations:
            lines.extend(f"- {item.behavior} ({item.file_path or '-'})" for item in report.observations)
        else:
            lines.append("Nenhuma.")
        lines.extend(
            [
                "",
                "Fontes baixadas e integridade:",
                *self._render_source_integrity_lines(report),
                "",
                "Scripts e arquivos encontrados nos sources:",
                *self._render_source_tree_lines(report),
                "",
                "Git:",
                f"  Disponível: {report.git.available}",
                f"  Último commit: {report.git.last_commit or '-'}",
                f"  Data: {report.git.last_commit_date or '-'}",
                f"  Autor: {report.git.last_commit_author or '-'}",
                "",
                "Aviso:",
                verdict.disclaimer or "Auditoria estática reduz risco, mas não garante segurança absoluta.",
            ]
        )
        return "\n".join(lines) + "\n"

    def _render_source_integrity_lines(self, report: AuditReport) -> list[str]:
        source_integrity = report.source_integrity
        if source_integrity is None:
            return ["  nao verificado"]
        summary = source_integrity.summary
        lines = [
            f"  total_sources: {summary.get('total_sources', 0)}",
            f"  valid_checksums: {summary.get('valid_checksums', 0)}",
            f"  skipped_checksums: {summary.get('skipped_checksums', 0)}",
            f"  invalid_checksums: {summary.get('invalid_checksums', 0)}",
            f"  pgp_valid: {summary.get('pgp_valid', 0)}",
            f"  pgp_invalid: {summary.get('pgp_invalid', 0)}",
            f"  upstream_confirmed: {summary.get('upstream_confirmed', 0)}",
        ]
        for source in source_integrity.sources:
            lines.append(
                f"  - {source.name}: {source.kind}, {source.checksum_status}, "
                f"{source.risk}, badges={','.join(source.badges) or '-'}"
            )
        return lines

    def _render_source_tree_lines(self, report: AuditReport) -> list[str]:
        source_tree = report.source_tree
        if source_tree is None:
            return ["  nao verificado"]
        summary = source_tree.summary
        return [
            f"  files_scanned: {summary.get('files_scanned', 0)}",
            f"  scripts_found: {summary.get('scripts_found', 0)}",
            f"  binaries_found: {summary.get('binaries_found', 0)}",
            f"  package_managers_detected: {', '.join(summary.get('package_managers_detected', [])) or '-'}",
            f"  lockfiles_detected: {', '.join(summary.get('lockfiles_detected', [])) or '-'}",
        ]

    def _render_dependency_lines(self, report: AuditReport) -> list[str]:
        dependency_audit = report.dependency_audit
        if dependency_audit is None:
            return ["  nao verificado"]
        data = dependency_audit.to_dict()
        summary = data.get("summary", {})
        lines = [
            f"  official: {summary.get('official', 0)}",
            f"  aur: {summary.get('aur', 0)}",
            f"  missing: {summary.get('missing', 0)}",
            f"  unknown: {summary.get('unknown', 0)}",
        ]
        for dep in dependency_audit.dependencies:
            lines.append(f"  - {dep.name}: {dep.kind} ({dep.source_field})")
        return lines

    def _load_known_bad_indicators(self) -> list[dict[str, str]]:
        data_path = Path(__file__).resolve().parents[2] / "data" / "known_bad_indicators.json"
        try:
            payload = json.loads(data_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        indicators = payload.get("indicators", [])
        if not isinstance(indicators, list):
            return []
        normalized: list[dict[str, str]] = []
        for item in indicators:
            if isinstance(item, dict) and item.get("value"):
                normalized.append({key: str(value) for key, value in item.items()})
        return normalized

    def verify_hashes(self, package_dir: Path, expected: dict[str, str]) -> tuple[bool, list[str]]:
        return compare_hashes(package_dir, expected)

    def _scan_text_file(self, rel: str, text: str, file_kind: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = text.splitlines()
        assignment_context = (
            self._assignment_context(lines) if file_kind == "PKGBUILD" else [None] * len(lines)
        )
        function_context = self._line_contexts(lines)
        stripped_lines: list[str] = []
        comment_lines: list[str] = []
        remote_rule = next(
            rule for rule in self.rules if rule.id == "critical.remote-shell-pipe"
        )
        remote_pattern = re.compile(remote_rule.regex, re.IGNORECASE)
        for raw_line in lines:
            stripped, comment = strip_inline_comment(raw_line)
            stripped_lines.append(stripped.rstrip())
            comment_lines.append(comment.rstrip())

        for index, raw_line in enumerate(lines, start=1):
            stripped_line = stripped_lines[index - 1]
            declarative_key = assignment_context[index - 1]
            for rule, pattern in self._compiled_rules:
                if file_kind not in rule.file_kinds:
                    continue
                if (
                    declarative_key in PKGBUILD_DECLARATIVE_KEYS
                    and rule.id not in RULES_ALLOWED_IN_DECLARATIVE_KEYS
                ):
                    continue
                if (
                    rule.id == "medium.download-outside-source"
                    and remote_pattern.search(stripped_line)
                ):
                    continue
                match = pattern.search(stripped_line)
                if match:
                    findings.append(
                        self._finding_from_rule(
                            rule,
                            rel,
                            index,
                            raw_line,
                            matched_text=match.group(0),
                            context=function_context[index - 1],
                        )
                    )
                    continue

                if file_kind in {"PKGBUILD", "INSTALL"}:
                    node_match = NODE_INSTALL_RE.search(stripped_line)
                    if node_match:
                        in_install = file_kind == "INSTALL"
                        severity = "CRITICAL" if in_install else "INFO"
                        classification = "CONCRETE_FAILURE" if in_install else "OBSERVATION"
                        impact = "RED" if in_install else "NONE"
                        rule_id = (
                            "NODE_INSTALL_IN_INSTALL_SCRIPT"
                            if in_install
                            else "NODE_DEPENDENCY_MANAGER_IN_PKGBUILD"
                        )
                        findings.append(
                            Finding(
                                rule_id=rule_id,
                                name="Node/Bun dependency manager em fluxo AUR",
                                classification=classification,
                                severity=severity,
                                status_impact=impact,
                                category="dependency_manager",
                                file_path=rel,
                                line_start=index,
                                matched_text=node_match.group(0),
                                command=node_match.group(0),
                                behavior=(
                                    "Dependency manager executado em scriptlet .install."
                                    if in_install
                                    else "Dependency manager observado no fluxo de build."
                                ),
                                why_it_matters=(
                                    "Scriptlets .install rodam durante instalação/upgrade e não devem buscar dependências dinâmicas."
                                    if in_install
                                    else "Uso em build pode ser normal quando há lockfile coerente; sem lockfile vira revisão concreta."
                                ),
                                evidence=raw_line.strip()[:300],
                                description=(
                                    "Gerenciador Node/Bun pode baixar dependencias externas e executar "
                                    "scripts de ciclo de vida durante build/install."
                                ),
                                risk_explanation=(
                                    "Esse padrao foi relevante em ataques recentes contra o AUR, onde "
                                    "pacotes aparentemente legitimos passaram a instalar dependencias npm/Bun maliciosas."
                                ),
                                recommendation=(
                                    "Revise lockfiles, scripts preinstall/install/postinstall/prepare, nomes de dependencias "
                                    "e se o uso pertence ao upstream oficial."
                                ),
                                context=function_context[index - 1],
                            )
                        )
                if file_kind == "INSTALL":
                    install_manager_match = INSTALL_SCRIPT_DEP_MANAGER_RE.search(stripped_line)
                    if install_manager_match:
                        findings.append(
                            Finding(
                                rule_id="INSTALL_SCRIPT_DEPENDENCY_MANAGER",
                                name="Dependency manager em scriptlet .install",
                                classification="CONCRETE_FAILURE",
                                severity="CRITICAL",
                                status_impact="RED",
                                category="dependency_manager",
                                file_path=rel,
                                line_start=index,
                                matched_text=install_manager_match.group(0),
                                command=install_manager_match.group(0),
                                behavior="Scriptlet .install executa instalação dinâmica de dependências.",
                                why_it_matters="Instalação dinâmica em .install é comportamento crítico e compatível com campanhas recentes no AUR.",
                                evidence=raw_line.strip()[:300],
                                description="Dependency manager executado durante evento de instalação/upgrade/removal.",
                                risk_explanation="Scriptlets .install rodam no sistema instalado e não devem baixar/instalar dependências dinâmicas.",
                                recommendation="Revisar manualmente e usar IA/especialista antes de instalar.",
                                context=function_context[index - 1],
                            )
                        )
                    install_download_match = re.search(r"\b(?:curl|wget)\b", stripped_line, re.IGNORECASE)
                    if install_download_match and not remote_pattern.search(stripped_line):
                        findings.append(
                            Finding(
                                rule_id="INSTALL_SCRIPT_REMOTE_DOWNLOAD",
                                name="Download remoto em scriptlet .install",
                                classification="CONCRETE_FAILURE",
                                severity="CRITICAL",
                                status_impact="RED",
                                category="remote_download",
                                file_path=rel,
                                line_start=index,
                                matched_text=install_download_match.group(0),
                                command=install_download_match.group(0),
                                behavior="Scriptlet .install executa downloader remoto.",
                                why_it_matters="Scriptlets rodam no sistema do usuário durante install/upgrade; rede nessa fase é comportamento crítico.",
                                evidence=raw_line.strip()[:300],
                                description=(
                                    "Scriptlet .install chama downloader remoto durante eventos de instalação."
                                ),
                                risk_explanation=(
                                    "Scriptlets rodam no sistema do usuário durante instalação/upgrade/remocao; "
                                    "download remoto nesse ponto pode puxar payload fora do AUR."
                                ),
                                recommendation=(
                                    "Revisar manualmente PKGBUILD, .SRCINFO, *.install, sources e logs; "
                                    "usar IA/especialista antes de instalar."
                                ),
                                context=function_context[index - 1],
                            )
                        )
                    persistence_match = INSTALL_SCRIPT_PERSISTENCE_RE.search(stripped_line)
                    if persistence_match:
                        findings.append(
                            Finding(
                                rule_id="INSTALL_SCRIPT_PERSISTENCE",
                                name="Persistencia em scriptlet .install",
                                classification="CONCRETE_FAILURE",
                                severity="CRITICAL",
                                status_impact="RED",
                                category="persistence",
                                file_path=rel,
                                line_start=index,
                                matched_text=persistence_match.group(0),
                                command=persistence_match.group(0),
                                behavior="Scriptlet .install tenta ativar persistência ou alterar perfil de shell.",
                                why_it_matters="Persistência automática em scriptlet é compatível com falhas reais do AUR.",
                                evidence=raw_line.strip()[:300],
                                description=(
                                    "Scriptlet .install contem systemd enable/start, cron, autostart ou alteração de shell profile."
                                ),
                                risk_explanation=(
                                    "Scriptlets rodam durante instalacao/upgrade/remocao e podem criar persistencia "
                                    "sem revisao manual clara."
                                ),
                                recommendation="Revise integralmente o scriptlet e confirme se a persistencia e esperada.",
                                context=function_context[index - 1],
                            )
                        )
                normal_build_match = NORMAL_BUILD_TOOL_RE.search(stripped_line)
                if normal_build_match:
                    findings.append(
                        Finding(
                            rule_id="NORMAL_BUILD_TOOL_OBSERVED",
                            name="Ferramenta de build comum observada",
                            classification="OBSERVATION",
                            severity="INFO",
                            status_impact="NONE",
                            category="normal_build_tool",
                            file_path=rel,
                            line_start=index,
                            matched_text=normal_build_match.group(0),
                            command=normal_build_match.group(0),
                            behavior="Comando de build comum em contexto normal.",
                            why_it_matters="make/cmake/meson/cargo build/go build/npm run build/pnpm build não são red flags isoladas.",
                            evidence=raw_line.strip()[:300],
                            description="Comando de build comum registrado como observação.",
                            recommendation="Sem ação necessária salvo se combinado com execução remota, exfiltração ou persistência.",
                            context=function_context[index - 1],
                        )
                    )

                comment = comment_lines[index - 1]
                if comment and pattern.search(comment):
                    findings.append(
                        Finding(
                            id=f"info.comment.{rule.id}",
                            name=f"Padrao sensivel em comentario: {rule.name}",
                            severity="INFO",
                            file_path=rel,
                            line_start=index,
                            matched_text=raw_line.strip()[:300],
                            description="O padrao aparece em comentario e nao foi tratado como execucao.",
                            recommendation="Confirme se o comentario nao documenta uma acao esperada pelo script.",
                            context=function_context[index - 1],
                        )
                    )

        findings.extend(self._scan_multiline(rel, lines, stripped_lines, file_kind))
        return findings

    def _scan_known_bad_indicators(self, package_dir: Path) -> list[Finding]:
        if not self.known_bad_indicators:
            return []
        findings: list[Finding] = []
        for path in iter_text_files(package_dir):
            rel = path.relative_to(package_dir).as_posix()
            text, _ = safe_read_text(path)
            contexts = self._line_contexts(text.splitlines())
            for line_number, raw_line in enumerate(text.splitlines(), start=1):
                stripped, comment = strip_inline_comment(raw_line)
                for item in self.known_bad_indicators:
                    value = item.get("value", "")
                    if not value:
                        continue
                    pattern = re.compile(rf"\b{re.escape(value)}\b", re.IGNORECASE)
                    if pattern.search(stripped):
                        findings.append(
                            Finding(
                                rule_id="AUR_MALICIOUS_DEPENDENCY_PATTERN",
                                name="Indicador conhecido de campanha",
                                classification="CONCRETE_FAILURE",
                                severity="CRITICAL",
                                status_impact="RED",
                                category="known_campaign_indicator",
                                file_path=rel,
                                line_start=line_number,
                                matched_text=value,
                                command=value,
                                behavior="IOC conhecido encontrado em conteúdo ativo.",
                                why_it_matters="Dependência/indicador associado a campanha documentada do AUR/npm.",
                                evidence=raw_line.strip()[:300],
                                related_incident_id="aur_2026_atomic_arch",
                                related_incident_year=2026,
                                related_incident_name="AUR 2026 Atomic Arch npm/Bun dependency campaign",
                                references=[
                                    "https://archlinux.org/news/active-aur-malicious-packages-incident/",
                                    "https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency",
                                ],
                                description=(
                                    "Indicador conhecido encontrado em lista local editavel. "
                                    "Confirme com fontes oficiais antes de assumir comprometimento."
                                ),
                                risk_explanation=(
                                    f"O indicador {value} foi associado a {item.get('campaign', 'campanha conhecida')} "
                                    "em fonte externa registrada localmente."
                                ),
                                recommendation=(
                                    "Interrompa o fluxo automatico, revise o diff, verifique fontes oficiais e trate como "
                                    "achado critico ate esclarecimento manual."
                                ),
                                context=contexts[line_number - 1] if contexts else "",
                            )
                        )
                    elif comment and pattern.search(comment):
                        findings.append(
                            Finding(
                                rule_id="AUR_MALICIOUS_DEPENDENCY_PATTERN_COMMENT",
                                name="Indicador conhecido citado em comentario",
                                classification="INFO",
                                severity="INFO",
                                status_impact="NONE",
                                category="known_campaign_indicator",
                                file_path=rel,
                                line_start=line_number,
                                matched_text=value,
                                command=value,
                                behavior="IOC conhecido citado em comentário.",
                                why_it_matters="Comentário não é execução nem dependência ativa.",
                                evidence=raw_line.strip()[:300],
                                description="Indicador conhecido aparece apenas em comentario.",
                                risk_explanation=(
                                    "Comentario nao e execucao, mas a mencao deve ser entendida no contexto do pacote."
                                ),
                                recommendation="Revise o comentario e confirme que nao documenta dependencia ativa.",
                            )
                        )
        return findings

    def _scan_known_incident_patterns(self, package_dir: Path, package_name: str) -> list[Finding]:
        findings: list[Finding] = []
        for path in iter_text_files(package_dir):
            rel = path.relative_to(package_dir).as_posix()
            file_kind = classify_file(path)
            text, _ = safe_read_text(path)
            lines = text.splitlines()
            contexts = self._line_contexts(lines)
            for line_number, raw_line in enumerate(lines, start=1):
                stripped, comment = strip_inline_comment(raw_line)
                if not stripped.strip():
                    continue
                for match in match_known_incident_patterns(
                    line=stripped,
                    file_kind=file_kind,
                    package_name=package_name,
                    full_text=text,
                ):
                    incident = match.incident
                    if incident.get("id") == "AUR_2018_CURL_PIPE_BASH":
                        continue
                    findings.append(
                        Finding(
                            rule_id=str(incident["id"]),
                            name=str(incident["label"]),
                            classification="CONCRETE_FAILURE",
                            severity=str(incident.get("severity", "CRITICAL")),
                            status_impact="RED",
                            category="known_incident_pattern",
                            file_path=rel,
                            line_start=line_number,
                            matched_text=match.matched_text,
                            command=match.matched_text,
                            behavior=str(incident.get("explanation", "")),
                            why_it_matters=str(incident.get("explanation", "")),
                            evidence=raw_line.strip()[:300],
                            related_incident_id=str(incident.get("id") or ""),
                            related_incident_year=int(incident["year"]) if incident.get("year") else None,
                            related_incident_name=str(incident.get("label") or incident.get("name") or ""),
                            references=list(incident.get("references") or ([incident["reference"]] if incident.get("reference") else [])),
                            description=str(incident.get("explanation", "")),
                            risk_explanation=str(incident.get("explanation", "")),
                            recommendation=str(incident.get("recommendation", "")),
                            context=contexts[line_number - 1] if contexts else "",
                            source="known_incident_pattern",
                            incident_year=int(incident["year"]) if incident.get("year") else None,
                            incident_name=str(incident["label"]),
                            incident_reference=str(incident.get("reference") or ""),
                            incident_similarity=match.similarity,
                        )
                    )
                for incident in configured_indicator_matches(stripped):
                    indicator = str(incident.get("matched_indicator") or "")
                    active_ioc = self._configured_ioc_is_active(
                        indicator=indicator,
                        line=stripped,
                        file_kind=file_kind,
                        context=contexts[line_number - 1] if contexts else "",
                    )
                    findings.append(
                        Finding(
                            rule_id="KNOWN_AUR_INCIDENT_IOC" if active_ioc else "KNOWN_AUR_INCIDENT_IOC_OBSERVED",
                            name=(
                                "IOC configurável de incidente AUR"
                                if active_ioc
                                else "IOC configurável observado sem ação crítica"
                            ),
                            classification="CONCRETE_FAILURE" if active_ioc else "OBSERVATION",
                            severity=str(incident.get("severity") or "CRITICAL") if active_ioc else "INFO",
                            status_impact="RED" if active_ioc else "NONE",
                            category="known_incident_pattern",
                            file_path=rel,
                            line_start=line_number,
                            matched_text=indicator,
                            command=indicator,
                            behavior=(
                                "IOC conhecido encontrado em contexto ativo."
                                if active_ioc
                                else "IOC conhecido citado sem escrita/execução relacionada."
                            ),
                            why_it_matters=(
                                f"O indicador {indicator} está associado a {incident.get('name', 'incidente AUR conhecido')}."
                                if active_ioc
                                else "Não há impacto de status sem contexto executável ou alteração relacionada."
                            ),
                            evidence=raw_line.strip()[:300],
                            related_incident_id=str(incident.get("id") or ""),
                            related_incident_year=int(incident["year"]) if incident.get("year") else None,
                            related_incident_name=str(incident.get("name") or incident.get("label") or ""),
                            references=list(incident.get("references") or ([incident["reference"]] if incident.get("reference") else [])),
                            description=(
                                "Indicador encontrado em data/known_aur_incidents.json, arquivo local "
                                "editável sem consulta online em runtime."
                            ),
                            risk_explanation=(
                                f"O indicador {indicator} está associado a {incident.get('name', 'incidente AUR conhecido')}."
                            ),
                            recommendation=str(
                                incident.get("recommendation")
                                or "Revisar manualmente e usar IA/especialista antes de instalar."
                            ),
                            context=contexts[line_number - 1] if contexts else "",
                            source="known_incident_config",
                            incident_year=int(incident["year"]) if incident.get("year") else None,
                            incident_name=str(incident.get("name") or incident.get("id") or ""),
                            incident_reference=str(incident.get("reference") or ""),
                            incident_similarity=f"Encontrado IOC configurável: {indicator}",
                        )
                    )
                if comment:
                    for incident in configured_indicator_matches(comment):
                        indicator = str(incident.get("matched_indicator") or "")
                        findings.append(
                            Finding(
                                rule_id="KNOWN_AUR_INCIDENT_IOC_COMMENT",
                                name="IOC configurável citado em comentário",
                                classification="INFO",
                                severity="INFO",
                                status_impact="NONE",
                                category="known_incident_pattern",
                                file_path=rel,
                                line_start=line_number,
                                matched_text=indicator,
                                command=indicator,
                                behavior="IOC conhecido citado em comentário.",
                                why_it_matters="Comentário não é execução nem alteração.",
                            evidence=raw_line.strip()[:300],
                            related_incident_id=str(incident.get("id") or ""),
                            related_incident_year=int(incident["year"]) if incident.get("year") else None,
                            related_incident_name=str(incident.get("name") or incident.get("id") or ""),
                            references=list(incident.get("references") or ([incident["reference"]] if incident.get("reference") else [])),
                            description="Indicador conhecido aparece apenas em comentário.",
                            risk_explanation=(
                                "Comentário não é execução, mas a menção deve ser entendida no contexto do pacote."
                                ),
                                recommendation="Revise o comentário e confirme que não documenta dependência ativa.",
                                context=contexts[line_number - 1] if contexts else "",
                                source="known_incident_config",
                                incident_year=int(incident["year"]) if incident.get("year") else None,
                                incident_name=str(incident.get("name") or incident.get("id") or ""),
                                incident_reference=str(incident.get("reference") or ""),
                                incident_similarity=f"IOC citado em comentário: {indicator}",
                            )
                        )
        return findings

    def _scan_recent_sensitive_diff(self, git_result: Any) -> list[Finding]:
        diff = getattr(git_result, "recent_diff", "") or ""
        findings: list[Finding] = []
        if not diff:
            return findings
        for line_number, raw_line in enumerate(diff.splitlines(), start=1):
            if raw_line.startswith("+++") or raw_line.startswith("---"):
                continue
            match = RECENT_SENSITIVE_ADDITION_RE.search(raw_line)
            if not match:
                continue
            command = match.group(0).lstrip("+").strip()
            severity = (
                "CRITICAL"
                if re.search(
                    r"curl\b[^|]*\|\s*(?:bash|sh)|wget\b[^|]*\|\s*(?:bash|sh)|"
                    r"atomic-lockfile|lockfile-js|js-digest|\.bashrc|\.zshrc|\.profile|config\.fish|"
                    r"systemctl\s+enable",
                    command,
                    re.IGNORECASE,
                )
                else "HIGH"
            )
            findings.append(
                Finding(
                    rule_id="AUR_RECENT_SENSITIVE_CHANGE",
                    name="Mudanca recente sensivel no AUR",
                    classification="CONCRETE_FAILURE" if severity == "CRITICAL" else "CONCRETE_SUSPICION",
                    severity=severity,
                    status_impact="RED" if severity == "CRITICAL" else "ORANGE",
                    category="recent_sensitive_change",
                    file_path="Git diff",
                    line_start=line_number,
                    matched_text=raw_line[:300],
                    command=command,
                    behavior="Diff recente adiciona comando perigoso.",
                    why_it_matters="Recência isolada não pesa; mudança recente só afeta status quando adiciona comportamento concreto perigoso.",
                    evidence=raw_line[:300],
                    description=(
                        "Diff recente adiciona comando sensivel em PKGBUILD, .SRCINFO ou scriptlet .install."
                    ),
                    risk_explanation=(
                        "Atualizacao recente foi combinada com mudanca tecnica objetiva, padrao compativel "
                        "com incidentes de supply chain observados no AUR."
                    ),
                    recommendation="Revise o commit, mantenedor, diffs e origem da dependencia antes de continuar.",
                    source="git",
                )
            )
        return findings

    def _configured_ioc_is_active(
        self,
        *,
        indicator: str,
        line: str,
        file_kind: str,
        context: str,
    ) -> bool:
        lower_indicator = indicator.lower()
        lower_line = line.lower()
        if lower_indicator in {".bashrc", ".zshrc", ".profile", "config.fish"}:
            return bool(
                file_kind == "INSTALL"
                and re.search(
                    r"(?:>>?|tee\s+-a|sed\s+-i|printf\b|echo\b|cat\b).*(?:\.bashrc|\.zshrc|\.profile|config\.fish)",
                    lower_line,
                )
            )
        if lower_indicator in {"curl | bash", "curl | sh", "wget | bash", "wget | sh"}:
            return bool(re.search(r"\b(?:curl|wget)\b[^|;\n]*\|\s*(?:bash|sh)\b", lower_line))
        if lower_indicator == "systemctl enable":
            return bool(re.search(r"\bsystemctl\s+enable\b", lower_line))
        if lower_indicator in {"atomic-lockfile", "js-digest", "lockfile-js"}:
            return bool(
                re.search(r"\b(?:npm|bun|pnpm|yarn|npx|bunx)\b", lower_line)
                or context in {"build()", "prepare()", "package()", "post_install()", "pre_install()"}
                or file_kind in {"PKGBUILD", "INSTALL", "AUX"}
            )
        return True

    def _scan_dependency_manager_lockfiles(
        self,
        package_dir: Path,
        findings: list[Finding],
    ) -> list[Finding]:
        results: list[Finding] = []
        tool_map = {
            "npm": re.compile(r"\bnpm\s+(?:install|i)\b|\bnpx\b", re.IGNORECASE),
            "pnpm": re.compile(r"\bpnpm\s+(?:install|dlx)\b", re.IGNORECASE),
            "yarn": re.compile(r"\byarn\s+(?:install|dlx)\b", re.IGNORECASE),
            "bun": re.compile(r"\bbun\s+install\b|\bbunx\b", re.IGNORECASE),
            "cargo": re.compile(r"\bcargo\s+install\b", re.IGNORECASE),
            "go": re.compile(r"\bgo\s+install\s+.*@latest\b", re.IGNORECASE),
            "pip": re.compile(r"\bpip\s+install\b|\bpython\s+-m\s+pip\s+install\b", re.IGNORECASE),
            "poetry": re.compile(r"\bpoetry\s+install\b", re.IGNORECASE),
            "composer": re.compile(r"\bcomposer\s+(?:install|update)\b", re.IGNORECASE),
        }
        seen: set[tuple[str, str, int | None]] = set()
        for finding in findings:
            text = f"{finding.command or ''} {finding.matched_text}"
            for tool, pattern in tool_map.items():
                if not pattern.search(text):
                    continue
                if finding.file_path.endswith(".install"):
                    continue
                lockfiles = LOCKFILES_BY_TOOL.get(tool, ())
                if any((package_dir / name).exists() for name in lockfiles):
                    continue
                key = (tool, finding.file_path, finding.line_start)
                if key in seen:
                    continue
                seen.add(key)
                results.append(
                    Finding(
                        rule_id="DEPENDENCY_MANAGER_WITHOUT_LOCKFILE",
                        name="Gerenciador de dependencias sem lockfile",
                        classification="CONCRETE_SUSPICION",
                        severity="REVIEW",
                        status_impact="YELLOW",
                        category="dependency_manager",
                        file_path=finding.file_path,
                        line_start=finding.line_start,
                        matched_text=finding.matched_text,
                        command=finding.command,
                        behavior=f"Uso de {tool} para instalação dinâmica sem lockfile correspondente.",
                        why_it_matters="Sem lockfile, o build pode resolver dependências diferentes e executar lifecycle scripts não fixados.",
                        evidence=finding.matched_text,
                        description=(
                            f"Uso de {tool} detectado sem lockfile correspondente no repositorio auditado."
                        ),
                        risk_explanation=(
                            "Ausencia de lockfile reduz reprodutibilidade e pode permitir que o build/install "
                            "resolva dependencias diferentes ao longo do tempo."
                        ),
                        recommendation=(
                            "Revise se o upstream versiona lockfile; prefira lockfile fixado e comandos reprodutiveis."
                        ),
                        context=finding.context,
                    )
                )
        return results

    def _assignment_context(self, lines: list[str]) -> list[str | None]:
        contexts: list[str | None] = [None] * len(lines)
        assignment_re = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")
        active_key: str | None = None
        balance = 0
        for index, raw_line in enumerate(lines):
            stripped, _ = strip_inline_comment(raw_line)
            if active_key:
                contexts[index] = active_key
                balance += stripped.count("(") - stripped.count(")")
                if balance <= 0:
                    active_key = None
                continue
            match = assignment_re.match(stripped)
            if not match:
                continue
            key = match.group(1)
            contexts[index] = key
            value = match.group(2).strip()
            if value.startswith("("):
                balance = value.count("(") - value.count(")")
                if balance > 0:
                    active_key = key
        return contexts

    def _line_contexts(self, lines: list[str]) -> list[str]:
        contexts = [""] * len(lines)
        generic_start_re = re.compile(r"^\s*(?:function\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(\))?\s*\{")
        active_name: str | None = None
        depth = 0
        for index, raw_line in enumerate(lines, start=1):
            stripped, _ = strip_inline_comment(raw_line)
            if active_name is None:
                match = generic_start_re.match(stripped)
                if not match:
                    continue
                active_name = match.group(1)
                depth = 0
            contexts[index - 1] = f"{active_name}()"
            depth += stripped.count("{") - stripped.count("}")
            if active_name is not None:
                if depth <= 0:
                    active_name = None
        return contexts

    def _scan_multiline(
        self,
        rel: str,
        lines: list[str],
        stripped_lines: list[str],
        file_kind: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        contexts = self._line_contexts(lines)
        remote_rule = next(
            rule for rule in self.rules if rule.id == "critical.remote-shell-pipe"
        )
        remote_pattern = re.compile(remote_rule.regex, re.IGNORECASE)
        for index in range(len(stripped_lines)):
            if not re.search(r"\b(?:curl|wget|bash|sh)\b", stripped_lines[index], re.IGNORECASE):
                continue
            if remote_pattern.search(stripped_lines[index]):
                continue
            window = " ".join(
                part.strip().rstrip("\\")
                for part in stripped_lines[index : min(index + 3, len(stripped_lines))]
            )
            if file_kind in remote_rule.file_kinds and remote_pattern.search(window):
                line_end = min(index + 3, len(stripped_lines))
                for end_index in range(index, min(index + 3, len(stripped_lines))):
                    partial = " ".join(
                        part.strip().rstrip("\\")
                        for part in stripped_lines[index : end_index + 1]
                    )
                    if remote_pattern.search(partial):
                        line_end = end_index + 1
                        break
                findings.append(
                    self._finding_from_rule(
                        remote_rule,
                        rel,
                        index + 1,
                        " ".join(line.strip() for line in lines[index : index + 3])[:300],
                        matched_text=window[:300],
                        line_end=line_end,
                        context=contexts[index],
                    )
                )
        return findings

    def _finding_from_rule(
        self,
        rule: Rule,
        rel: str,
        line: int,
        raw_line: str,
        matched_text: str | None = None,
        line_end: int | None = None,
        context: str = "",
    ) -> Finding:
        snippet = raw_line.strip()[:300]
        matched = (matched_text or snippet).strip()[:300]
        knowledge = explain_text(matched or snippet, rule.id, rule.severity)
        incident_fields = {}
        classification, status_impact, severity = self._impact_for_rule(rule)
        if rule.id == "critical.remote-shell-pipe":
            incident_fields = {
                "incident_year": 2018,
                "related_incident_year": 2018,
                "related_incident_id": "aur_2018_curl_pipe_bash",
                "incident_name": "Padrão 2018: execução remota direta via curl | bash",
                "incident_reference": "https://lists.archlinux.org/pipermail/aur-general/2018-July/034151.html",
                "incident_similarity": (
                    "Encontrada execução remota direta equivalente a incidente AUR de 2018."
                ),
            }
        return Finding(
            id=rule.id,
            name=rule.name,
            classification=classification,
            severity=severity,
            status_impact=status_impact,
            category=rule.category if rule.category != "other" else knowledge.category,
            file_path=rel,
            line_start=line,
            line_end=line_end,
            matched_text=matched,
            command=rule.command or knowledge.command,
            behavior=knowledge.description if knowledge.command else rule.description,
            why_it_matters=knowledge.aur_risk if knowledge.command else rule.description,
            evidence=matched,
            description=knowledge.description if knowledge.command else rule.description,
            risk_explanation=knowledge.aur_risk if knowledge.command else rule.description,
            recommendation=self._knowledge_recommendation(knowledge, rule.recommendation)
            if knowledge.command
            else rule.recommendation,
            context=context,
            **incident_fields,
        )

    def _impact_for_rule(self, rule: Rule) -> tuple[str, str, str]:
        if rule.severity == "CRITICAL":
            return "CONCRETE_FAILURE", "RED", "CRITICAL"
        if rule.id == "high.systemd-start-enable":
            return "CONCRETE_FAILURE", "RED", "CRITICAL"
        if rule.id == "high.account-or-cron-change":
            return "CONCRETE_SUSPICION", "YELLOW", "REVIEW"
        if rule.id in {
            "medium.install-directive",
            "medium.download-outside-source",
            "medium.dependency-manager",
            "medium.skipped-or-weak-checksum",
            "high.network-tooling",
            "high.generated-code-or-remote-tool",
        }:
            return "OBSERVATION", "NONE", "INFO"
        if rule.severity == "HIGH":
            return "CONCRETE_SUSPICION", "YELLOW", "REVIEW"
        if rule.severity in {"MEDIUM", "REVIEW"}:
            return "CONCRETE_SUSPICION", "YELLOW", "REVIEW"
        if rule.severity == "LOW":
            return "OBSERVATION", "NONE", "INFO"
        return "INFO", "NONE", "INFO"

    def _scan_install_files(self, package_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        for path in sorted(package_dir.rglob("*.install")):
            if ".git" in path.parts:
                continue
            rel = path.relative_to(package_dir).as_posix()
            findings.append(
                Finding(
                    id="medium.install-file-present",
                    name="Arquivo .install presente",
                    classification="OBSERVATION",
                    severity="INFO",
                    status_impact="NONE",
                    file_path=rel,
                    line=None,
                    snippet=rel,
                    behavior="Arquivo .install presente.",
                    why_it_matters=".install roda em eventos de instalação/upgrade/removal; a presença isolada é observação, não suspeita.",
                    evidence=rel,
                    description=(
                        "Scriptlets ALPM podem executar funcoes durante instalacao, "
                        "upgrade e remocao do pacote."
                    ),
                    recommendation="Sem ação necessária se o scriptlet não contém rede, persistência, dependency manager ou alteração sensível.",
                )
            )
        return findings

    def _scan_pkgbuild_specific(self, package_dir: Path) -> list[Finding]:
        pkgbuild = package_dir / "PKGBUILD"
        if not pkgbuild.exists():
            return [
                Finding(
                    id="high.pkgbuild-missing",
                    name="PKGBUILD ausente",
                    classification="CONCRETE_SUSPICION",
                    severity="REVIEW",
                    status_impact="YELLOW",
                    file_path="PKGBUILD",
                    line=None,
                    snippet="PKGBUILD not found",
                    behavior="PKGBUILD ausente.",
                    why_it_matters="Sem PKGBUILD não há auditoria mínima suficiente.",
                    evidence="PKGBUILD not found",
                    description="Nao ha PKGBUILD para auditar.",
                    recommendation="Confirme se o download do pacote AUR foi concluido corretamente.",
                )
            ]
        text, _ = safe_read_text(pkgbuild)
        findings = self._scan_package_function_writes(text)
        assignments = parse_pkgbuild_assignments(text)
        dependencies = []
        for key in ("depends", "makedepends", "checkdepends", "optdepends"):
            dependencies.extend(assignments.get(key, []))
        findings.extend(self._scan_sensitive_dependencies(dependencies, "PKGBUILD"))
        return findings

    def _scan_package_function_writes(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = text.splitlines()
        for name, start, end in self._function_blocks(lines):
            if not name.startswith("package"):
                continue
            for offset in range(start, end + 1):
                raw_line = lines[offset - 1]
                stripped, _ = strip_inline_comment(raw_line)
                if "$pkgdir" in stripped or "${pkgdir}" in stripped:
                    continue
                if PACKAGE_WRITE_OUTSIDE_RE.search(stripped):
                    critical_target = bool(
                        re.search(
                            r"/(?:etc|boot|root|home)\b|/etc/systemd/system|/etc/pacman\.conf|"
                            r"/etc/pacman\.d/mirrorlist|\.bashrc|\.zshrc|\.profile|config\.fish",
                            stripped,
                            re.IGNORECASE,
                        )
                    )
                    findings.append(
                        Finding(
                            id="high.package-writes-outside-pkgdir",
                            name="Escrita fora de $pkgdir em package()",
                            classification="CONCRETE_FAILURE" if critical_target else "CONCRETE_SUSPICION",
                            severity="CRITICAL" if critical_target else "REVIEW",
                            status_impact="RED" if critical_target else "YELLOW",
                            file_path="PKGBUILD",
                            line=offset,
                            snippet=raw_line.strip()[:300],
                            behavior="package() escreve diretamente fora de $pkgdir.",
                            why_it_matters=(
                                "package() deve montar arquivos no diretório de pacote; escrita direta em /etc, /boot, /root, /home ou perfis de shell é crítica."
                                if critical_target
                                else "package() deve montar arquivos no diretório de pacote; escrita direta em /usr sem $pkgdir exige revisão."
                            ),
                            evidence=raw_line.strip()[:300],
                            description=(
                                "package() deve instalar arquivos dentro de $pkgdir. "
                                "Escrita direta fora de $pkgdir pode afetar o sistema real."
                            ),
                            recommendation=(
                                "Use caminhos como \"$pkgdir/usr/...\" ou \"$pkgdir/etc/...\"."
                            ),
                        )
                    )
        return findings

    def _function_blocks(self, lines: list[str]) -> list[tuple[str, int, int]]:
        blocks: list[tuple[str, int, int]] = []
        active_name: str | None = None
        start_line = 0
        depth = 0
        for index, raw_line in enumerate(lines, start=1):
            stripped, _ = strip_inline_comment(raw_line)
            if active_name is None:
                match = FUNCTION_START_RE.match(stripped)
                if not match:
                    continue
                active_name = match.group("name")
                start_line = index
                depth = stripped.count("{") - stripped.count("}")
                if depth <= 0:
                    blocks.append((active_name, start_line, index))
                    active_name = None
                continue
            depth += stripped.count("{") - stripped.count("}")
            if depth <= 0:
                blocks.append((active_name, start_line, index))
                active_name = None
        if active_name is not None:
            blocks.append((active_name, start_line, len(lines)))
        return blocks

    def _scan_srcinfo_consistency(self, package_dir: Path) -> list[Finding]:
        pkgbuild = package_dir / "PKGBUILD"
        srcinfo = package_dir / ".SRCINFO"
        if not pkgbuild.exists() or not srcinfo.exists():
            return []
        pkgbuild_text, _ = safe_read_text(pkgbuild)
        srcinfo_text, _ = safe_read_text(srcinfo)
        pkg_values = parse_pkgbuild_assignments(pkgbuild_text)
        src_values = parse_srcinfo(srcinfo_text)
        variables = {key: values[0] for key, values in pkg_values.items() if values}
        findings: list[Finding] = []

        for key in sorted(PROTECTED_COMPARE_KEYS):
            pkg_set = {
                self._normalize_pkgbuild_value(value, variables)
                for value in pkg_values.get(key, [])
            }
            src_set = {self._normalize_value(value) for value in src_values.get(key, [])}
            if not pkg_set or not src_set or pkg_set == src_set:
                continue
            findings.append(
                Finding(
                    id="medium.pkgbuild-srcinfo-mismatch",
                    name="Divergencia entre PKGBUILD e .SRCINFO",
                    classification="OBSERVATION",
                    severity="INFO",
                    status_impact="NONE",
                    file_path=".SRCINFO",
                    line=None,
                    snippet=f"{key}: PKGBUILD={sorted(pkg_set)} .SRCINFO={sorted(src_set)}",
                    behavior="PKGBUILD e .SRCINFO divergem em metadados.",
                    why_it_matters="Divergência deve ser revisada, mas não é falha concreta sem comportamento perigoso.",
                    evidence=f"{key}: PKGBUILD={sorted(pkg_set)} .SRCINFO={sorted(src_set)}",
                    description="Metadados textuais divergem entre PKGBUILD e .SRCINFO.",
                    recommendation=(
                        "Nao confie cegamente no .SRCINFO; revise o PKGBUILD como fonte executavel."
                    ),
                )
            )
        return findings

    def _scan_metadata(self, metadata: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        if not metadata:
            return findings

        if not metadata.get("Maintainer"):
            findings.append(
                Finding(
                    id="low.no-maintainer",
                    name="Pacote sem mantenedor",
                    severity="LOW",
                    file_path="AUR metadata",
                    line=None,
                    snippet="Maintainer empty",
                    description="Pacotes sem mantenedor podem receber menos revisao continua.",
                    recommendation="Revise historico e popularidade com cuidado extra.",
                    source="aur-metadata",
                )
            )
        if metadata.get("OutOfDate"):
            findings.append(
                Finding(
                    id="low.out-of-date",
                    name="Pacote marcado como out-of-date",
                    severity="LOW",
                    file_path="AUR metadata",
                    line=None,
                    snippet=f"OutOfDate={metadata.get('OutOfDate')}",
                    description="O pacote foi marcado como desatualizado no AUR.",
                    recommendation="Confirme se o PKGBUILD ainda aponta para fontes corretas.",
                    source="aur-metadata",
                )
            )
        popularity = self._float_or_none(metadata.get("Popularity"))
        if popularity is not None and popularity < 0.01:
            findings.append(
                Finding(
                    id="info.low-popularity",
                    name="Baixa popularidade",
                    severity="INFO",
                    file_path="AUR metadata",
                    line=None,
                    snippet=f"Popularity={popularity}",
                    description="Baixa popularidade pode indicar menor revisao comunitaria.",
                    recommendation="Use historico Git, mantenedor e upstream para formar julgamento.",
                    source="aur-metadata",
                )
            )

        last_modified = self._float_or_none(metadata.get("LastModified"))
        if last_modified is not None and time.time() - last_modified < 7 * 24 * 60 * 60:
            findings.append(
                Finding(
                    id="info.recently-modified",
                    name="Pacote alterado muito recentemente",
                    severity="INFO",
                    file_path="AUR metadata",
                    line=None,
                    snippet=f"LastModified={format_unix_timestamp(last_modified)}",
                    description="Alteracoes muito recentes ainda podem nao ter recebido revisao ampla.",
                    recommendation="Leia o diff do ultimo commit antes de instalar.",
                    source="aur-metadata",
                )
            )

        dependencies = []
        for key in ("Depends", "MakeDepends", "CheckDepends", "OptDepends"):
            value = metadata.get(key) or []
            if isinstance(value, list):
                dependencies.extend(value)
        findings.extend(self._scan_sensitive_dependencies(dependencies, "AUR metadata"))
        return findings

    def _scan_neutral_observations(
        self,
        package_dir: Path,
        package_name: str,
        metadata: dict[str, Any],
        source_integrity: Any,
    ) -> list[Finding]:
        findings: list[Finding] = []
        if package_name.endswith("-bin"):
            findings.append(
                self._neutral_observation(
                    "OBS_PACKAGE_BIN",
                    "Pacote -bin",
                    "AUR metadata",
                    None,
                    package_name,
                    "Pacote -bin observado.",
                    "Pacotes -bin podem ser legítimos quando a origem é coerente com o upstream.",
                )
            )
        upstream = str(metadata.get("URL") or "")
        if "github.com" in upstream.lower():
            findings.append(
                self._neutral_observation(
                    "OBS_GITHUB_UPSTREAM",
                    "GitHub upstream",
                    "AUR metadata",
                    None,
                    upstream,
                    "Pacote usa GitHub upstream.",
                    "GitHub é comum em projetos AUR e não indica risco por si só.",
                )
            )
        for source in getattr(source_integrity, "sources", []) or []:
            raw = str(getattr(source, "raw", "") or getattr(source, "url", "") or "")
            lower = raw.lower()
            kind = str(getattr(source, "kind", ""))
            if "github.com" in lower:
                findings.append(
                    self._neutral_observation(
                        "OBS_GITHUB_SOURCE",
                        "Source no GitHub",
                        "PKGBUILD",
                        None,
                        raw,
                        "Source usa GitHub.",
                        "GitHub upstream ou release é comum e não altera o resultado sem evidência concreta.",
                    )
                )
            if kind in {"archive", "appimage"} or lower.endswith((".tar.gz", ".tgz", ".tar.xz", ".tar.zst", ".zip", ".appimage")):
                findings.append(
                    self._neutral_observation(
                        "OBS_SOURCE_ARCHIVE",
                        "Source compactado ou AppImage",
                        "PKGBUILD",
                        None,
                        raw,
                        "Source é arquivo compactado/AppImage.",
                        "Tarballs, zips e AppImages são formatos comuns e não são suspeitos isoladamente.",
                    )
                )
        for path in sorted(package_dir.rglob("*.desktop")):
            if ".git" in path.parts:
                continue
            findings.append(
                self._neutral_observation(
                    "OBS_DESKTOP_FILE",
                    "Arquivo .desktop",
                    path.relative_to(package_dir).as_posix(),
                    None,
                    path.name,
                    "Arquivo .desktop empacotado.",
                    ".desktop é metadado normal de integração com desktop e não altera o resultado.",
                )
            )
        for path in sorted(package_dir.rglob("*.service")):
            if ".git" in path.parts:
                continue
            findings.append(
                self._neutral_observation(
                    "OBS_SYSTEMD_UNIT_PACKAGED",
                    "Unit systemd empacotada",
                    path.relative_to(package_dir).as_posix(),
                    None,
                    path.name,
                    "Unit systemd apenas empacotada.",
                    "Unit systemd em $pkgdir/usr/lib/systemd/system é observação; crítico é enable/start automático.",
                )
            )
        return findings

    def _neutral_observation(
        self,
        rule_id: str,
        name: str,
        file_path: str,
        line: int | None,
        snippet: str,
        behavior: str,
        explanation: str,
    ) -> Finding:
        return Finding(
            rule_id=rule_id,
            name=name,
            classification="OBSERVATION",
            severity="INFO",
            status_impact="NONE",
            category="observation",
            file_path=file_path,
            line_start=line,
            matched_text=snippet[:300],
            behavior=behavior,
            why_it_matters=explanation,
            evidence=snippet[:300],
            description=behavior,
            risk_explanation=explanation,
            recommendation="Nenhuma ação necessária sem evidência concreta adicional.",
            source="observation",
        )

    def _scan_sensitive_dependencies(self, dependencies: list[str], file_path: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for dep in dependencies:
            dep_name = str(dep).split(":", 1)[0]
            dep_name = re.split(r"[<>=]", dep_name, maxsplit=1)[0].strip()
            if dep_name in SENSITIVE_DEPENDENCIES and dep_name not in seen:
                seen.add(dep_name)
                findings.append(
                    Finding(
                        id="low.sensitive-dependency",
                        name="Dependencia potencialmente sensivel",
                        severity="LOW",
                        file_path=file_path,
                        line=None,
                        snippet=dep,
                        description="Dependencia associada a rede, clipboard, chaves ou segredos.",
                        recommendation="Confirme se essa dependencia e coerente com a finalidade do pacote.",
                        source="dependency",
                    )
                )
        return findings

    def _scan_ecosystem_files(self, package_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        for path in iter_text_files(package_dir):
            rel = path.relative_to(package_dir).as_posix()
            name = path.name
            text, _ = safe_read_text(path)
            if name == "package.json":
                findings.extend(self._scan_package_json(rel, text))
            elif name == "build.rs":
                findings.extend(self._scan_rust_build_rs(rel, text))
            elif name.endswith(".go"):
                findings.extend(self._scan_go_file(rel, text))
            elif name in {"setup.py", "pyproject.toml", "setup.cfg"}:
                findings.extend(self._scan_python_packaging(rel, text))
            elif name in {"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"}:
                findings.extend(self._scan_gradle(rel, text))
        return findings

    def _scan_package_json(self, rel: str, text: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return findings
        scripts = parsed.get("scripts")
        if not isinstance(scripts, dict):
            return findings
        dangerous_re = re.compile(DANGEROUS_NPM_SCRIPT_RE, re.IGNORECASE)
        for script_name in sorted(NPM_LIFECYCLE_SCRIPTS & set(scripts)):
            command = str(scripts[script_name])
            line = self._line_number_for_text(text, f'"{script_name}"')
            findings.append(
                Finding(
                    id="info.npm-lifecycle-script",
                    name="Script npm de ciclo de vida",
                    classification="OBSERVATION",
                    severity="INFO",
                    status_impact="NONE",
                    file_path=rel,
                    line=line,
                    snippet=f"{script_name}: {command}",
                    behavior="package.json contém script lifecycle.",
                    why_it_matters="Lifecycle scripts podem ser normais; só afetam status quando contêm execução remota, IOC ou payload acionado.",
                    evidence=f"{script_name}: {command}",
                    description="Scripts npm podem executar durante build/test/install.",
                    recommendation="Revise o script e seus comandos transitivos.",
                    source="ecosystem",
                )
            )
            if dangerous_re.search(command):
                remote_exec = re.search(
                    r"\b(?:curl|wget)\b[^|;\n]*\|\s*(?:bash|sh)\b|"
                    r"\b(?:bash|sh)\s+<\(\s*(?:curl|wget)\b",
                    command,
                    re.IGNORECASE,
                )
                findings.append(
                    Finding(
                        id="high.npm-dangerous-lifecycle-script",
                        name="Script npm com comando sensivel",
                        classification="CONCRETE_FAILURE" if remote_exec else "OBSERVATION",
                        severity="CRITICAL" if remote_exec else "INFO",
                        status_impact="RED" if remote_exec else "NONE",
                        file_path=rel,
                        line=line,
                        snippet=f"{script_name}: {command}",
                        behavior=(
                            "Lifecycle npm executa conteúdo remoto diretamente."
                            if remote_exec
                            else "Lifecycle npm contém comando sensível observado."
                        ),
                        why_it_matters=(
                            "Execução remota direta em lifecycle é comportamento crítico."
                            if remote_exec
                            else "Comando sensível em script de source não é red flag isolada sem acionamento perigoso concreto."
                        ),
                        evidence=f"{script_name}: {command}",
                        description="Script npm chama shell, downloader, Python, base64 ou eval.",
                        recommendation="Audite esse script e arquivos chamados antes de permitir build.",
                        source="ecosystem",
                    )
                )
        return findings

    def _scan_rust_build_rs(self, rel: str, text: str) -> list[Finding]:
        pattern = re.compile(r"Command::new|curl|wget|git|ssh|https?://|HOME|\.ssh", re.IGNORECASE)
        return self._find_pattern_lines(
            rel,
            text,
            pattern,
            "medium.rust-build-rs-sensitive",
            "build.rs com comportamento sensivel",
            "INFO",
            "build.rs pode executar comandos durante compilacao Rust.",
            "Revise chamadas de processo, rede e acesso a HOME/.ssh.",
            classification="OBSERVATION",
            status_impact="NONE",
        )

    def _scan_go_file(self, rel: str, text: str) -> list[Finding]:
        return self._find_pattern_lines(
            rel,
            text,
            re.compile(r"//go:generate"),
            "medium.go-generate-directive",
            "Diretiva go:generate",
            "INFO",
            "Diretivas go:generate podem executar comandos arbitrarios se acionadas.",
            "Revise a diretiva e evite rodar go generate sem aprovacao explicita.",
            classification="OBSERVATION",
            status_impact="NONE",
        )

    def _scan_python_packaging(self, rel: str, text: str) -> list[Finding]:
        pattern = re.compile(
            r"\b(?:os\.system|subprocess|eval|exec|requests|urllib|socket|base64)\b",
            re.IGNORECASE,
        )
        return self._find_pattern_lines(
            rel,
            text,
            pattern,
            "medium.python-packaging-sensitive",
            "Empacotamento Python com comportamento sensivel",
            "INFO",
            "setup/pyproject usa execucao dinamica, rede ou primitives sensiveis.",
            "Revise o fluxo de build Python antes de executar.",
            classification="OBSERVATION",
            status_impact="NONE",
        )

    def _scan_gradle(self, rel: str, text: str) -> list[Finding]:
        pattern = re.compile(
            r"\b(?:exec|curl|wget|ProcessBuilder|Runtime\.getRuntime|apply\s+from)\b",
            re.IGNORECASE,
        )
        return self._find_pattern_lines(
            rel,
            text,
            pattern,
            "medium.gradle-sensitive",
            "Gradle com comportamento sensivel",
            "INFO",
            "Script Gradle pode executar processos, baixar scripts ou aplicar arquivos remotos.",
            "Revise o script e lockfiles antes de executar ./gradlew ou gradle.",
            classification="OBSERVATION",
            status_impact="NONE",
        )

    def _find_pattern_lines(
        self,
        rel: str,
        text: str,
        pattern: re.Pattern[str],
        finding_id: str,
        name: str,
        severity: str,
        description: str,
        recommendation: str,
        classification: str = "OBSERVATION",
        status_impact: str = "NONE",
    ) -> list[Finding]:
        findings: list[Finding] = []
        for index, raw_line in enumerate(text.splitlines(), start=1):
            stripped, _ = strip_inline_comment(raw_line)
            if pattern.search(stripped):
                findings.append(
                    Finding(
                        id=finding_id,
                        name=name,
                        classification=classification,
                        severity=severity,
                        status_impact=status_impact,
                        file_path=rel,
                        line=index,
                        snippet=raw_line.strip()[:300],
                        behavior=description,
                        why_it_matters="Achado de ecossistema registrado para revisão contextual; não altera status sem comportamento perigoso concreto.",
                        evidence=raw_line.strip()[:300],
                        description=description,
                        recommendation=recommendation,
                        source="ecosystem",
                    )
                )
        return findings

    def _line_number_for_text(self, text: str, needle: str) -> int | None:
        for index, line in enumerate(text.splitlines(), start=1):
            if needle in line:
                return index
        return None

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        seen: set[tuple[str, str, int | None, int | None, str]] = set()
        unique: list[Finding] = []
        for item in findings:
            enriched = self._enrich_finding(item)
            key = (
                enriched.rule_id,
                enriched.file_path,
                enriched.line_start,
                enriched.line_end,
                enriched.matched_text,
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(enriched)
        return sorted(unique, key=lambda item: item.sort_key())

    def _enrich_finding(self, finding: Finding) -> Finding:
        knowledge = explain_text(
            finding.matched_text or finding.description,
            finding.rule_id,
            finding.severity,
        )
        category = finding.category
        if category in {"other", ""}:
            category = knowledge.category or category_for_rule(finding.rule_id)
        command = finding.command or knowledge.command
        description = finding.description
        risk_explanation = finding.risk_explanation
        recommendation = finding.recommendation
        if knowledge.command:
            description = knowledge.description
            risk_explanation = knowledge.aur_risk
            recommendation = self._knowledge_recommendation(knowledge, recommendation)
        return Finding(
            rule_id=finding.rule_id,
            name=finding.name,
            classification=finding.classification,
            severity=finding.severity,
            status_impact=finding.status_impact,
            category=category,
            file_path=finding.file_path,
            line_start=finding.line_start,
            line_end=finding.line_end,
            matched_text=finding.matched_text,
            command=command,
            behavior=finding.behavior,
            why_it_matters=finding.why_it_matters,
            evidence=finding.evidence,
            related_incident_id=finding.related_incident_id,
            related_incident_year=finding.related_incident_year,
            related_incident_name=finding.related_incident_name,
            references=finding.references,
            description=description,
            risk_explanation=risk_explanation,
            recommendation=recommendation,
            context=finding.context,
            source=finding.source,
            incident_year=finding.incident_year,
            incident_name=finding.incident_name,
            incident_reference=finding.incident_reference,
            incident_similarity=finding.incident_similarity,
        )

    def _knowledge_recommendation(self, knowledge: Any, fallback: str) -> str:
        parts = [
            knowledge.review,
            knowledge.recommendation or fallback,
            f"Quando aceitavel: {knowledge.acceptable_when}" if knowledge.acceptable_when else "",
            f"Quando suspeito: {knowledge.suspicious_when}" if knowledge.suspicious_when else "",
            f"Alternativa preferivel: {knowledge.preferred_alternative}"
            if knowledge.preferred_alternative
            else "",
        ]
        return " ".join(part for part in parts if part).strip()

    def _normalize_metadata(self, metadata: dict[str, Any]) -> dict[str, Any]:
        normalized = dict(metadata)
        for key in ("FirstSubmitted", "LastModified", "OutOfDate"):
            value = normalized.get(key)
            if value:
                normalized[f"{key}Local"] = format_unix_timestamp(value)
        return normalized

    def _normalize_value(self, value: str) -> str:
        return str(value).strip().strip("'\"")

    def _normalize_pkgbuild_value(self, value: str, variables: dict[str, str]) -> str:
        normalized = self._normalize_value(value)
        for key, replacement in variables.items():
            normalized = normalized.replace(f"${{{key}}}", replacement)
            normalized = normalized.replace(f"${key}", replacement)
        return normalized

    def _float_or_none(self, value: Any) -> float | None:
        try:
            if value is None:
                return None
            return float(value)
        except (TypeError, ValueError):
            return None
