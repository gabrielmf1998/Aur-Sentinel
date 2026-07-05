from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any

from aur_sentinel.aur.rpc import AurRpcClient

from .models import Finding


@dataclass
class DependencyInfo:
    name: str
    kind: str
    source_field: str
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "source_field": self.source_field,
            "detail": self.detail,
        }


@dataclass
class DependencyAuditReport:
    dependencies: list[DependencyInfo] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    depth: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "depth": self.depth,
            "dependencies": [item.to_dict() for item in self.dependencies],
            "findings": [item.to_dict() for item in self.findings],
            "summary": {
                "official": sum(1 for item in self.dependencies if item.kind == "official"),
                "aur": sum(1 for item in self.dependencies if item.kind == "aur"),
                "missing": sum(1 for item in self.dependencies if item.kind == "missing"),
                "unknown": sum(1 for item in self.dependencies if item.kind == "unknown"),
            },
        }


def audit_dependencies(metadata: dict[str, Any], depth: int = 1) -> DependencyAuditReport:
    report = DependencyAuditReport(depth=depth)
    deps: list[tuple[str, str]] = []
    for field in ("Depends", "MakeDepends", "CheckDepends", "OptDepends"):
        for raw_dep in metadata.get(field) or []:
            deps.append((_dep_name(str(raw_dep)), field))
    seen: set[str] = set()
    client = AurRpcClient()
    for dep, field in deps:
        if not dep or dep in seen:
            continue
        seen.add(dep)
        if _is_official(dep):
            report.dependencies.append(DependencyInfo(dep, "official", field))
            continue
        try:
            aur_package = client.info(dep)
            report.dependencies.append(DependencyInfo(dep, "aur", field, aur_package.name))
            report.findings.append(
                Finding(
                    rule_id="AUR_TRANSITIVE_DEPENDENCY",
                    name="Dependencia AUR transitiva",
                    classification="OBSERVATION",
                    severity="INFO",
                    status_impact="NONE",
                    category="dependency_audit",
                    file_path="AUR metadata",
                    matched_text=dep,
                    command=dep,
                    behavior="Dependência transitiva vem do AUR.",
                    why_it_matters="Dependências AUR ampliam escopo de auditoria, mas não são red flag concreta isolada.",
                    evidence=dep,
                    description="Dependencia nao encontrada nos repositorios oficiais e encontrada no AUR.",
                    risk_explanation="Dependencias AUR transitivas ampliam a superficie de supply chain e tambem exigem auditoria.",
                    recommendation="Audite a dependencia AUR antes de instalar o pacote principal.",
                    source="dependency_audit",
                )
            )
        except Exception:
            report.dependencies.append(DependencyInfo(dep, "missing", field))
            report.findings.append(
                Finding(
                    rule_id="DEPENDENCY_NOT_FOUND",
                    name="Dependencia nao encontrada",
                    classification="OBSERVATION",
                    severity="INFO",
                    status_impact="NONE",
                    category="dependency_audit",
                    file_path="AUR metadata",
                    matched_text=dep,
                    command=dep,
                    behavior="Dependência não encontrada automaticamente.",
                    why_it_matters="Pode exigir revisão de provides/opcionalidade, mas não é comportamento perigoso.",
                    evidence=dep,
                    description="Dependencia nao foi localizada em pacman -Si nem AUR RPC.",
                    risk_explanation="Pode indicar dependencia opcional, nome virtual ou metadado incorreto.",
                    recommendation="Confirme manualmente o pacote/provide correspondente.",
                    source="dependency_audit",
                )
            )
    return report


def _dep_name(raw: str) -> str:
    raw = raw.split(":", 1)[0]
    return re.split(r"[<>=]", raw, maxsplit=1)[0].strip()


def _is_official(package: str) -> bool:
    if shutil.which("pacman") is None:
        return False
    try:
        completed = subprocess.run(
            ["pacman", "-Si", package],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=8,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0
