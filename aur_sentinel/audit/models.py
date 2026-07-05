from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from .command_knowledge import category_for_rule


EvidenceKind = Literal["critical", "suspicious", "observation", "info"]

SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "OBSERVATION": 1,
    "REVIEW": 2,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

CLASSIFICATION_ORDER = {
    "INFO": 0,
    "OBSERVATION": 1,
    "CONCRETE_SUSPICION": 2,
    "CONCRETE_FAILURE": 3,
}

STATUS_IMPACT_ORDER = {
    "NONE": 0,
    "YELLOW": 1,
    "ORANGE": 2,
    "RED": 3,
}


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str
    regex: str
    description: str
    recommendation: str
    file_kinds: tuple[str, ...] = ("PKGBUILD", "INSTALL", "AUX")
    category: str = "other"
    command: str | None = None


@dataclass
class Evidence:
    kind: EvidenceKind
    title: str
    file_path: str | None
    line_start: int | None
    line_end: int | None
    snippet: str | None
    behavior: str
    explanation: str
    recommendation: str | None
    related_incident_id: str | None
    related_incident_name: str | None
    references: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "title": self.title,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "snippet": self.snippet,
            "behavior": self.behavior,
            "explanation": self.explanation,
            "recommendation": self.recommendation,
            "related_incident_id": self.related_incident_id,
            "related_incident_name": self.related_incident_name,
            "references": self.references,
        }


@dataclass(frozen=True)
class FinalVerdict:
    verdict: Literal[
        "NOT_VERIFIED",
        "OK_INSTALL",
        "SUSPICIOUS_ANALYZE",
        "CRITICAL_NOT_RECOMMENDED",
    ]
    label: str
    color: Literal["gray", "green", "orange", "red"]
    summary: str
    subtext: str
    disclaimer: str = ""
    reasons: tuple[str, ...] = ()
    recommendations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "label": self.label,
            "color": self.color,
            "summary": self.summary,
            "subtext": self.subtext,
            "disclaimer": self.disclaimer,
            "reasons": list(self.reasons),
            "recommendations": list(self.recommendations),
        }


@dataclass(frozen=True)
class InstallStatus:
    code: str
    text: str
    subtitle: str
    color: str
    reasons: tuple[str, ...] = ()
    recommendations: tuple[str, ...] = ()
    badges: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "text": self.text,
            "subtitle": self.subtitle,
            "color": self.color,
            "reasons": list(self.reasons),
            "recommendations": list(self.recommendations),
            "badges": list(self.badges),
        }


@dataclass(init=False)
class Finding:
    rule_id: str
    classification: str
    severity: str
    status_impact: str
    category: str
    file_path: str
    line_start: int | None
    line_end: int | None
    matched_text: str
    command: str | None
    behavior: str
    why_it_matters: str
    evidence: str
    related_incident_id: str | None
    related_incident_year: int | None
    related_incident_name: str | None
    references: list[str]
    description: str
    risk_explanation: str
    recommendation: str
    context: str
    name: str
    source: str = "static"
    incident_year: int | None = None
    incident_name: str | None = None
    incident_reference: str | None = None
    incident_similarity: str | None = None

    def __init__(
        self,
        rule_id: str | None = None,
        classification: str | None = None,
        severity: str = "INFO",
        status_impact: str | None = None,
        category: str | None = None,
        file_path: str = "",
        line_start: int | None = None,
        line_end: int | None = None,
        matched_text: str = "",
        command: str | None = None,
        behavior: str = "",
        why_it_matters: str = "",
        evidence: str = "",
        related_incident_id: str | None = None,
        related_incident_year: int | None = None,
        related_incident_name: str | None = None,
        references: list[str] | None = None,
        description: str = "",
        risk_explanation: str = "",
        recommendation: str = "",
        context: str = "",
        name: str = "",
        source: str = "static",
        id: str | None = None,
        line: int | None = None,
        snippet: str | None = None,
        incident_year: int | None = None,
        incident_name: str | None = None,
        incident_reference: str | None = None,
        incident_similarity: str | None = None,
    ) -> None:
        resolved_rule_id = rule_id or id or "unknown"
        resolved_classification = classification or _classification_for_legacy_severity(severity)
        resolved_status_impact = status_impact or _status_impact_for_classification(
            resolved_classification, severity
        )
        resolved_related_year = related_incident_year if related_incident_year is not None else incident_year
        resolved_related_id = related_incident_id
        if resolved_related_id is None and incident_year is not None:
            resolved_related_id = resolved_rule_id
        resolved_related_name = related_incident_name or incident_name
        resolved_references = list(references or [])
        if incident_reference:
            resolved_references.append(incident_reference)

        self.rule_id = resolved_rule_id
        self.classification = resolved_classification
        self.severity = severity
        self.status_impact = resolved_status_impact
        self.category = category or category_for_rule(resolved_rule_id)
        self.file_path = file_path
        self.line_start = line_start if line_start is not None else line
        self.line_end = line_end
        self.matched_text = matched_text if matched_text else (snippet or "")
        self.command = command
        self.behavior = behavior or description or resolved_rule_id
        self.why_it_matters = why_it_matters or risk_explanation or description
        self.evidence = evidence or self.matched_text
        self.related_incident_id = resolved_related_id
        self.related_incident_year = resolved_related_year
        self.related_incident_name = resolved_related_name
        self.references = sorted(set(resolved_references))
        self.description = description or self.behavior
        self.risk_explanation = risk_explanation or self.why_it_matters or self.description
        self.recommendation = recommendation
        self.context = context
        self.name = name or resolved_rule_id
        self.source = source
        self.incident_year = incident_year
        self.incident_name = incident_name
        self.incident_reference = incident_reference
        self.incident_similarity = incident_similarity

    @property
    def id(self) -> str:
        return self.rule_id

    @property
    def line(self) -> int | None:
        return self.line_start

    @property
    def snippet(self) -> str:
        return self.matched_text

    @property
    def evidence_kind(self) -> EvidenceKind:
        if self.classification == "CONCRETE_FAILURE" or self.status_impact == "RED":
            return "critical"
        if self.classification == "CONCRETE_SUSPICION" or self.status_impact in {"YELLOW", "ORANGE"}:
            return "suspicious"
        if self.classification == "OBSERVATION":
            return "observation"
        return "info"

    def sort_key(self) -> tuple[int, int, int, str, int]:
        return (
            -STATUS_IMPACT_ORDER.get(self.status_impact, 0),
            -CLASSIFICATION_ORDER.get(self.classification, 0),
            -SEVERITY_ORDER.get(self.severity, 0),
            self.file_path,
            self.line_start or 0,
        )

    def to_evidence(self) -> Evidence:
        return Evidence(
            kind=self.evidence_kind,
            title=self.name,
            file_path=self.file_path or None,
            line_start=self.line_start,
            line_end=self.line_end,
            snippet=self.matched_text or None,
            behavior=self.behavior,
            explanation=self.why_it_matters or self.risk_explanation or self.description,
            recommendation=self.recommendation or None,
            related_incident_id=self.related_incident_id,
            related_incident_name=self.related_incident_name or self.incident_name,
            references=self.references,
        )

    def to_dict(self) -> dict[str, Any]:
        data = self.to_evidence().to_dict()
        data.update(
            {
                "rule_id": self.rule_id,
                "id": self.rule_id,
                "category": self.category,
                "classification": self.classification,
                "file": self.file_path,
                "line": self.line_start,
                "line_start": self.line_start,
                "line_end": self.line_end,
                "command": self.command,
                "matched_text": self.matched_text,
                "evidence": self.evidence,
                "behavior": self.behavior,
                "why_it_matters": self.why_it_matters,
                "description": self.description,
                "risk_explanation": self.risk_explanation,
                "recommendation": self.recommendation,
                "context": self.context,
                "source": self.source,
                "related_incident_year": self.related_incident_year,
                "incident_year": self.incident_year,
                "incident_name": self.incident_name,
                "incident_similarity": self.incident_similarity,
            }
        )
        return data


@dataclass
class GitAuditResult:
    available: bool
    error: str | None = None
    last_commit: str = ""
    last_commit_date: str = ""
    last_commit_author: str = ""
    changed_files: list[str] = field(default_factory=list)
    log_oneline: str = ""
    show_stat: str = ""
    recent_diff: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "error": self.error,
            "last_commit": self.last_commit,
            "last_commit_date": self.last_commit_date,
            "last_commit_author": self.last_commit_author,
            "changed_files": self.changed_files,
            "log_oneline": self.log_oneline,
            "show_stat": self.show_stat,
            "recent_diff": self.recent_diff,
        }


@dataclass
class AuditReport:
    package_name: str
    package_dir: Path
    generated_at: str
    metadata: dict[str, Any]
    findings: list[Finding]
    file_hashes: dict[str, str]
    git: GitAuditResult
    audit_phases: dict[str, str] = field(default_factory=dict)
    source_integrity: Any | None = None
    source_tree: Any | None = None
    dependency_audit: Any | None = None
    archive_analysis: Any | None = None
    trust: Any | None = None

    @property
    def counts_by_severity(self) -> dict[str, int]:
        counts = {severity: 0 for severity in SEVERITY_ORDER}
        for item in self.findings:
            counts[item.severity] = counts.get(item.severity, 0) + 1
        return counts

    @property
    def counts_by_classification(self) -> dict[str, int]:
        counts = {
            "CONCRETE_FAILURE": 0,
            "CONCRETE_SUSPICION": 0,
            "OBSERVATION": 0,
            "INFO": 0,
        }
        for item in self.findings:
            counts[item.classification] = counts.get(item.classification, 0) + 1
        return counts

    @property
    def concrete_failures(self) -> list[Finding]:
        return [item for item in self.findings if item.evidence_kind == "critical"]

    @property
    def concrete_suspicions(self) -> list[Finding]:
        return [item for item in self.findings if item.evidence_kind == "suspicious"]

    @property
    def observations(self) -> list[Finding]:
        return [item for item in self.findings if item.evidence_kind == "observation"]

    @property
    def info(self) -> list[Finding]:
        return [item for item in self.findings if item.evidence_kind == "info"]

    @property
    def critical_evidence(self) -> list[Evidence]:
        evidence = [item.to_evidence() for item in self.concrete_failures]
        rule_ids = {item.rule_id for item in self.concrete_failures}
        if _has_checksum_invalid(self) and "SOURCE_CHECKSUM_INVALID" not in rule_ids:
            evidence.append(
                Evidence(
                    kind="critical",
                    title="Checksum inválido",
                    file_path="PKGBUILD",
                    line_start=None,
                    line_end=None,
                    snippet=None,
                    behavior="Checksum calculado diverge do valor declarado.",
                    explanation="Checksum inválido indica que a fonte baixada não corresponde ao PKGBUILD auditado.",
                    recommendation="Não instalar sem entender a divergência.",
                    related_incident_id=None,
                    related_incident_name=None,
                    references=[],
                )
            )
        if _has_pgp_invalid(self) and not any("PGP" in item.rule_id.upper() for item in self.concrete_failures):
            evidence.append(
                Evidence(
                    kind="critical",
                    title="PGP inválido",
                    file_path="PKGBUILD",
                    line_start=None,
                    line_end=None,
                    snippet=None,
                    behavior="Assinatura PGP inválida ou chave rejeitada.",
                    explanation="PGP inválido impede confiar que a fonte corresponde ao release assinado esperado.",
                    recommendation="Não instalar sem validar assinatura, chave e fonte manualmente.",
                    related_incident_id=None,
                    related_incident_name=None,
                    references=[],
                )
            )
        return evidence

    @property
    def suspicious_evidence(self) -> list[Evidence]:
        evidence = [item.to_evidence() for item in self.concrete_suspicions]
        partial = partial_or_failed_phases(self)
        if partial and not any(item.title == "Auditoria parcial" for item in evidence):
            evidence.append(
                Evidence(
                    kind="suspicious",
                    title="Auditoria parcial",
                    file_path=None,
                    line_start=None,
                    line_end=None,
                    snippet=", ".join(partial),
                    behavior="Uma etapa obrigatória falhou ou ficou parcial.",
                    explanation="Estado verde exige auditoria concluída nas etapas executadas; falha ou parcialidade precisa de revisão manual.",
                    recommendation="Reexecute a auditoria completa ou revise manualmente as etapas indicadas.",
                    related_incident_id=None,
                    related_incident_name=None,
                    references=[],
                )
            )
        return evidence

    @property
    def observation_evidence(self) -> list[Evidence]:
        return [item.to_evidence() for item in self.observations]

    @property
    def info_evidence(self) -> list[Evidence]:
        return [item.to_evidence() for item in self.info]

    @property
    def counts_by_category(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in self.findings:
            counts[item.category] = counts.get(item.category, 0) + 1
        return dict(sorted(counts.items()))

    @property
    def counts_by_file(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in self.findings:
            counts[item.file_path] = counts.get(item.file_path, 0) + 1
        return dict(sorted(counts.items()))

    @property
    def suspicious_command_count(self) -> int:
        return len(self.concrete_failures) + len(self.concrete_suspicions)

    @property
    def summary(self) -> dict[str, Any]:
        return {
            "total_findings": len(self.findings),
            "by_classification": self.counts_by_classification,
            "by_category": self.counts_by_category,
            "by_file": self.counts_by_file,
            "critical": len(self.concrete_failures),
            "suspicious": len(self.concrete_suspicions),
            "observations": len(self.observations),
            "info": len(self.info),
        }

    @property
    def has_critical(self) -> bool:
        return bool(self.concrete_failures)

    @property
    def final_verdict(self) -> FinalVerdict:
        return classify_final_result(self)

    @property
    def install_status(self) -> InstallStatus:
        verdict = self.final_verdict
        return InstallStatus(
            code=verdict.verdict,
            text=verdict.label,
            subtitle=verdict.subtext,
            color=verdict.color,
            reasons=verdict.reasons,
            recommendations=verdict.recommendations,
            badges=tuple(_completed_badges(self)),
        )

    @property
    def audit_completed(self) -> bool:
        phases = normalized_phases(self)
        return phases.get("initial_static_audit") == "completed"

    @property
    def audit_partial(self) -> bool:
        return bool(partial_or_failed_phases(self))

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda item: item.sort_key())

    def analyzed_bool(self) -> dict[str, bool]:
        status = self.analysis_status()
        return {
            key: value not in {"falhou", "não analisado", "erro", "parcial"}
            for key, value in status.items()
        }

    def analysis_status(self) -> dict[str, str]:
        phases = normalized_phases(self)
        source_summary = self.source_integrity.summary if self.source_integrity else {}
        tree_summary = self.source_tree.summary if self.source_tree else {}
        install_files = list(self.package_dir.rglob("*.install")) if self.package_dir.exists() else []
        checksums_status = "não aplicável"
        if self.source_integrity is not None:
            if source_summary.get("invalid_checksums", 0):
                checksums_status = "falhou"
            elif source_summary.get("valid_checksums", 0):
                checksums_status = "OK"
            elif source_summary.get("skipped_checksums", 0) or source_summary.get("missing_checksums", 0):
                checksums_status = "parcial"
        pgp_status = "não disponível"
        if self.source_integrity is not None:
            log_status = getattr(self.source_integrity, "makepkg_log_status", {}) or {}
            if source_summary.get("pgp_invalid", 0) or log_status.get("pgp_invalid", 0):
                pgp_status = "falhou"
            elif source_summary.get("pgp_valid", 0) or log_status.get("pgp_valid", 0):
                pgp_status = "OK"
        return {
            "pkgbuild": "analisado" if (self.package_dir / "PKGBUILD").exists() and phases.get("pkgbuild") != "failed" else "falhou",
            "srcinfo": "analisado" if (self.package_dir / ".SRCINFO").exists() else "não existe",
            "install_scripts": "analisado" if install_files else "não existe",
            "git_history": "analisado" if phases.get("git_history") == "completed" else "não analisado",
            "sources": "verificados" if self.source_integrity is not None or phases.get("source_verification") == "completed" else "não analisado",
            "archives": "extraídos/analisados" if self.archive_analysis is not None or phases.get("archive_analysis") == "completed" else "não analisado",
            "scripts": "analisados" if self.source_tree is not None or phases.get("source_tree_scan") == "completed" else "não analisado",
            "binaries": "analisados" if tree_summary.get("binaries_found", 0) else ("não encontrados" if self.source_tree is not None else "não analisado"),
            "checksums": checksums_status,
            "pgp": pgp_status,
        }

    def to_dict(self) -> dict[str, Any]:
        source_integrity_dict = (
            self.source_integrity.to_dict() if self.source_integrity is not None else {}
        )
        source_tree_dict = self.source_tree.to_dict() if self.source_tree is not None else {}
        dependency_audit_dict = (
            self.dependency_audit.to_dict() if self.dependency_audit is not None else {}
        )
        archive_analysis_dict = (
            self.archive_analysis.to_dict() if self.archive_analysis is not None else {}
        )
        verdict = self.final_verdict
        phases = normalized_phases(self)
        return {
            "package": self.package_name,
            "package_name": self.package_name,
            "audit_version": 4,
            "verdict": verdict.verdict,
            "label": verdict.label,
            "color": verdict.color,
            "summary": verdict.summary,
            "subtext": verdict.subtext,
            "disclaimer": verdict.disclaimer,
            "audit_completed": self.audit_completed,
            "audit_partial": self.audit_partial,
            "analyzed": self.analyzed_bool(),
            "analysis_status": self.analysis_status(),
            "critical_evidence": [item.to_dict() for item in self.critical_evidence],
            "suspicious_evidence": [item.to_dict() for item in self.suspicious_evidence],
            "observations": [item.to_dict() for item in self.observation_evidence],
            "info": [item.to_dict() for item in self.info_evidence],
            "install_anyway_available": verdict.verdict == "CRITICAL_NOT_RECOMMENDED",
            "recommendation": "; ".join(verdict.recommendations),
            "finding_summary": self.summary,
            "audit_phases": phases,
            "audit_completion": phases,
            "package_dir": str(self.package_dir),
            "generated_at": self.generated_at,
            "timestamp": self.generated_at,
            "source_integrity": source_integrity_dict,
            "source_tree": source_tree_dict,
            "dependency_audit": dependency_audit_dict,
            "archive_analysis": archive_analysis_dict,
            "metadata": self.metadata,
            "findings": [item.to_dict() for item in self.sorted_findings()],
            "file_hashes": self.file_hashes,
            "git": self.git.to_dict(),
            "security_notice": (
                "AUR packages are community-maintained. PKGBUILD files are executable Bash. "
                "This static audit reduces risk but does not prove the absence of malware."
            ),
        }


def classify_final_result(audit_result: AuditReport) -> FinalVerdict:
    phases = normalized_phases(audit_result)
    if phases.get("initial_static_audit") != "completed" or any(
        status == "cancelled" for status in phases.values()
    ):
        return FinalVerdict(
            verdict="NOT_VERIFIED",
            label="NÃO VERIFICADO",
            color="gray",
            summary="Execute a auditoria antes de decidir.",
            subtext="Execute a auditoria antes de decidir.",
            reasons=("A auditoria ainda não foi concluída ou foi cancelada.",),
            recommendations=("Execute a auditoria antes de decidir.",),
        )

    critical = audit_result.concrete_failures
    if _has_checksum_invalid(audit_result) or _has_pgp_invalid(audit_result) or critical:
        reasons = []
        if _has_checksum_invalid(audit_result):
            reasons.append("Checksum inválido encontrado.")
        if _has_pgp_invalid(audit_result):
            reasons.append("PGP inválido encontrado.")
        if critical:
            first = critical[0]
            location = first.file_path or "arquivo não informado"
            if first.line_start:
                location += f":{first.line_start}"
            reasons.append(f"Evidência crítica: {first.name} em {location}.")
        return FinalVerdict(
            verdict="CRITICAL_NOT_RECOMMENDED",
            label="CRÍTICO — NÃO RECOMENDADO",
            color="red",
            summary="Foi encontrado comportamento compatível com falha documentada do AUR.",
            subtext="Foi encontrado comportamento compatível com falhas reais do AUR/supply chain ou ação nociva concreta.",
            disclaimer="Auditoria estática reduz risco, mas não prova ausência de malware.",
            reasons=tuple(reasons),
            recommendations=(
                "Não instalar sem análise manual detalhada.",
                "Use IA/especialista e revise PKGBUILD, .SRCINFO, *.install, sources, diffs e logs.",
            ),
        )

    partial = partial_or_failed_phases(audit_result)
    suspicious = audit_result.concrete_suspicions
    if partial or suspicious:
        reasons = []
        if partial:
            reasons.append("Auditoria parcial: " + ", ".join(sorted(partial)))
        if suspicious:
            first = suspicious[0]
            location = first.file_path or "arquivo não informado"
            if first.line_start:
                location += f":{first.line_start}"
            reasons.append(f"Evidência suspeita: {first.name} em {location}.")
        return FinalVerdict(
            verdict="SUSPICIOUS_ANALYZE",
            label="SUSPEITO — ANALISAR",
            color="orange",
            summary="Foram encontrados pontos concretos que exigem revisão manual antes de instalar.",
            subtext="Foram encontrados pontos concretos que exigem revisão manual antes de instalar.",
            disclaimer="Auditoria estática reduz risco, mas não prova ausência de malware.",
            reasons=tuple(reasons),
            recommendations=(
                "Revise as evidências antes de instalar.",
                "Continue apenas se o comportamento for esperado e justificado pelo upstream.",
            ),
        )

    return FinalVerdict(
        verdict="OK_INSTALL",
        label="OK — PODE INSTALAR",
        color="green",
        summary="Nenhum comportamento nocivo ou padrão de falha AUR documentada foi encontrado na auditoria.",
        subtext="Nenhum comportamento nocivo ou padrão de falha AUR documentada foi encontrado na auditoria.",
        disclaimer="Isso não garante segurança absoluta; indica apenas baixo risco observado.",
        reasons=(
            "Nenhum comportamento crítico documentado foi encontrado.",
            "Nenhuma suspeita concreta foi encontrada.",
            "Observações neutras não alteraram o resultado.",
        ),
        recommendations=("Pode instalar se você aceita as limitações normais de auditoria estática.",),
    )


def normalized_phases(report: AuditReport) -> dict[str, str]:
    default_phases = {
        "aur_repo": "completed",
        "pkgbuild": "completed",
        "srcinfo": "completed" if (report.package_dir / ".SRCINFO").exists() else "not_applicable",
        "install_scripts": "completed",
        "git_history": "completed",
        "initial_static_audit": "completed",
        "source_verification": "not_run",
        "source_extraction": "not_run",
        "archive_analysis": "not_run",
        "deep_file_scan": "not_run",
        "source_tree_scan": "not_run",
        "dependency_audit": "not_run",
    }
    return {**default_phases, **report.audit_phases}


def partial_or_failed_phases(report: AuditReport) -> list[str]:
    phases = normalized_phases(report)
    relevant = {
        "aur_repo",
        "pkgbuild",
        "srcinfo",
        "install_scripts",
        "git_history",
        "initial_static_audit",
        "source_verification",
        "source_extraction",
        "archive_analysis",
        "deep_file_scan",
        "source_tree_scan",
    }
    bad_statuses = {"failed", "error", "partial", "partial_limit", "incomplete"}
    results = [
        name
        for name, status in phases.items()
        if name in relevant and status in bad_statuses
    ]
    if report.source_tree is not None and getattr(report.source_tree, "partial", False):
        results.append("source_tree_scan")
    if report.archive_analysis is not None and getattr(report.archive_analysis, "partial", False):
        results.append("archive_analysis")
    return sorted(set(results))


def determine_install_status(audit_result: AuditReport) -> InstallStatus:
    return audit_result.install_status


def _classification_for_legacy_severity(severity: str) -> str:
    if severity == "CRITICAL":
        return "CONCRETE_FAILURE"
    if severity in {"HIGH", "MEDIUM", "REVIEW"}:
        return "CONCRETE_SUSPICION"
    if severity in {"LOW", "OBSERVATION"}:
        return "OBSERVATION"
    return "INFO"


def _status_impact_for_classification(classification: str, severity: str) -> str:
    if classification == "CONCRETE_FAILURE":
        return "RED"
    if classification == "CONCRETE_SUSPICION":
        return "ORANGE" if severity == "HIGH" else "YELLOW"
    return "NONE"


def _has_checksum_invalid(report: AuditReport) -> bool:
    source_integrity = report.source_integrity
    if source_integrity is not None:
        try:
            if source_integrity.summary.get("invalid_checksums", 0):
                return True
        except AttributeError:
            pass
    return any(item.rule_id == "SOURCE_CHECKSUM_INVALID" for item in report.findings)


def _has_pgp_invalid(report: AuditReport) -> bool:
    source_integrity = report.source_integrity
    if source_integrity is not None:
        try:
            summary = source_integrity.summary
            if summary.get("pgp_invalid", 0):
                return True
            log_status = getattr(source_integrity, "makepkg_log_status", {}) or {}
            if log_status.get("pgp_invalid", 0):
                return True
        except AttributeError:
            pass
    return any(
        "PGP" in item.rule_id.upper() and "INVALID" in item.rule_id.upper()
        for item in report.findings
    )


def _completed_badges(report: AuditReport) -> list[str]:
    phases = normalized_phases(report)
    if (
        phases.get("source_verification") == "completed"
        and phases.get("source_extraction") == "completed"
        and phases.get("source_tree_scan") == "completed"
    ):
        return ["Auditoria completa concluída"]
    return []
