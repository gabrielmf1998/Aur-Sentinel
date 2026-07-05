from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .file_audit import parse_pkgbuild_assignments, safe_read_text
from .models import Finding


CHECKSUM_KEYS = ("b2sums", "sha512sums", "sha256sums", "sha1sums", "md5sums")
STRONG_CHECKSUMS = {"b2sums", "sha512sums", "sha256sums"}
WEAK_CHECKSUMS = {"sha1sums", "md5sums"}
ARCHIVE_EXTS = (
    ".tar.gz",
    ".tar.bz2",
    ".tar.xz",
    ".tar.zst",
    ".tgz",
    ".tbz2",
    ".txz",
    ".zip",
    ".gz",
    ".bz2",
    ".xz",
    ".zst",
)
SIGNATURE_EXTS = (".sig", ".asc", ".sign")
SUSPICIOUS_HOST_RE = re.compile(r"(pastebin|hastebin|transfer\.sh|tmpfiles|0x0\.st|file\.io|anonfiles|bit\.ly|tinyurl|goo\.gl)", re.I)


@dataclass
class SourceEntry:
    index: int
    raw: str
    name: str
    url: str
    kind: str
    domain: str = ""
    scheme: str = ""
    checksum_algorithm: str | None = None
    declared_checksum: str | None = None
    calculated_hashes: dict[str, str] = field(default_factory=dict)
    checksum_status: str = "not_checked"
    pgp_status: str = "not_checked"
    upstream_status: str = "not_checked"
    risk: str = "not_verified"
    badges: list[str] = field(default_factory=list)
    local_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "raw": self.raw,
            "name": self.name,
            "url": self.url,
            "kind": self.kind,
            "domain": self.domain,
            "scheme": self.scheme,
            "checksum_algorithm": self.checksum_algorithm,
            "declared_checksum": self.declared_checksum,
            "calculated_hashes": self.calculated_hashes,
            "checksum_status": self.checksum_status,
            "pgp_status": self.pgp_status,
            "upstream_status": self.upstream_status,
            "risk": self.risk,
            "badges": self.badges,
            "local_path": self.local_path,
        }


@dataclass
class SourceIntegrityReport:
    sources: list[SourceEntry] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    makepkg_log_status: dict[str, int] = field(default_factory=dict)
    validpgpkeys: list[str] = field(default_factory=list)
    noextract: list[str] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, Any]:
        return {
            "total_sources": len(self.sources),
            "valid_checksums": sum(1 for item in self.sources if item.checksum_status == "valid"),
            "skipped_checksums": sum(1 for item in self.sources if item.checksum_status == "skip"),
            "invalid_checksums": sum(1 for item in self.sources if item.checksum_status == "invalid"),
            "missing_checksums": sum(1 for item in self.sources if item.checksum_status == "missing"),
            "pgp_valid": sum(1 for item in self.sources if item.pgp_status == "valid"),
            "pgp_invalid": sum(1 for item in self.sources if item.pgp_status == "invalid"),
            "pgp_not_verified": sum(1 for item in self.sources if item.pgp_status in {"not_checked", "not_verified"}),
            "upstream_confirmed": sum(1 for item in self.sources if item.upstream_status == "confirmed"),
            "upstream_not_available": sum(1 for item in self.sources if item.upstream_status in {"not_checked", "not_available"}),
            "validpgpkeys": len(self.validpgpkeys),
        }

    def to_dict(self) -> dict[str, Any]:
        data = self.summary
        data["sources"] = [item.to_dict() for item in self.sources]
        data["findings"] = [item.to_dict() for item in self.findings]
        data["makepkg_log_status"] = self.makepkg_log_status
        data["validpgpkeys_values"] = self.validpgpkeys
        data["noextract"] = self.noextract
        return data


def parse_source_integrity(
    package_dir: Path,
    sources_dir: Path | None = None,
    upstream_url: str = "",
) -> SourceIntegrityReport:
    pkgbuild = package_dir / "PKGBUILD"
    if not pkgbuild.exists():
        return SourceIntegrityReport()
    text, _ = safe_read_text(pkgbuild)
    assignments = parse_pkgbuild_assignments(text)
    sources = _collect_sources(assignments)
    entries: list[SourceEntry] = []
    findings: list[Finding] = []
    for index, source in enumerate(sources):
        entry = _source_entry(index, source, assignments, upstream_url)
        _attach_local_hashes(entry, sources_dir or package_dir)
        _classify_source_status(entry, upstream_url)
        entries.append(entry)
        findings.extend(_findings_for_entry(entry))
    return SourceIntegrityReport(
        sources=entries,
        findings=findings,
        validpgpkeys=assignments.get("validpgpkeys", []),
        noextract=assignments.get("noextract", []),
    )


def parse_makepkg_verifysource_log(text: str) -> dict[str, int]:
    lower = text.lower()
    return {
        "sources_downloaded": len(re.findall(r"(?:downloading|found|retrieving)", lower)),
        "checksums_valid": len(re.findall(r"(?:passed|validating source files.*finished|integrity checks.*passed)", lower)),
        "checksums_invalid": len(re.findall(r"(?:failed|did not pass|one or more files did not pass)", lower)),
        "checksums_skip": len(re.findall(r"\bskip\b", lower)),
        "pgp_valid": len(re.findall(r"(?:good signature|signature.*valid)", lower)),
        "pgp_invalid": len(re.findall(r"(?:bad signature|signature.*failed|unknown public key)", lower)),
        "source_unavailable": len(re.findall(r"(?:404|not found|could not resolve|failed to download|connection refused)", lower)),
    }


def _collect_sources(assignments: dict[str, list[str]]) -> list[str]:
    sources: list[str] = []
    for key, values in assignments.items():
        if key == "source" or key.startswith("source_"):
            sources.extend(values)
    return sources


def _source_entry(
    index: int,
    raw: str,
    assignments: dict[str, list[str]],
    upstream_url: str,
) -> SourceEntry:
    name, url = _split_source_name(raw)
    parsed = urlparse(url)
    kind = classify_source(url)
    checksum_algorithm, declared_checksum = _checksum_for_index(index, assignments)
    entry = SourceEntry(
        index=index,
        raw=raw,
        name=name,
        url=url,
        kind=kind,
        domain=parsed.netloc.lower(),
        scheme=parsed.scheme.lower(),
        checksum_algorithm=checksum_algorithm,
        declared_checksum=declared_checksum,
    )
    if declared_checksum and declared_checksum.upper() == "SKIP":
        entry.checksum_status = "skip"
    elif checksum_algorithm in WEAK_CHECKSUMS:
        entry.checksum_status = "weak"
    elif declared_checksum is None and not kind.startswith("vcs_") and kind != "signature":
        entry.checksum_status = "missing"
    return entry


def _split_source_name(raw: str) -> tuple[str, str]:
    if "::" in raw:
        name, url = raw.split("::", 1)
    else:
        url = raw
        path = urlparse(url).path if re.match(r"^[a-z][a-z0-9+.-]*://", url, re.I) else raw
        name = Path(path).name or raw.rstrip("/").split("/")[-1]
    return name, url


def classify_source(url: str) -> str:
    lower = url.lower()
    if lower.startswith(("git+", "git://")) or lower.endswith(".git"):
        return "vcs_git"
    if lower.startswith(("svn+", "svn://")):
        return "vcs_svn"
    if lower.startswith(("hg+", "hg://")):
        return "vcs_mercurial"
    if lower.startswith(("bzr+", "bzr://")):
        return "vcs_bazaar"
    if lower.endswith(SIGNATURE_EXTS):
        return "signature"
    if lower.endswith(".appimage"):
        return "appimage"
    if lower.endswith((".deb", ".rpm", ".jar")):
        return "binary_package"
    if lower.endswith(ARCHIVE_EXTS):
        return "archive"
    if re.match(r"^[a-z][a-z0-9+.-]*://", url, re.I):
        return "url"
    return "local_file"


def _checksum_for_index(index: int, assignments: dict[str, list[str]]) -> tuple[str | None, str | None]:
    for key in CHECKSUM_KEYS:
        values = assignments.get(key, [])
        if index < len(values):
            return key, values[index]
    return None, None


def _attach_local_hashes(entry: SourceEntry, sources_dir: Path) -> None:
    candidates = [sources_dir / entry.name, sources_dir / Path(entry.name).name]
    local_path = next((path for path in candidates if path.is_file()), None)
    if not local_path:
        return
    entry.local_path = str(local_path)
    entry.calculated_hashes = {
        "sha256": _hash_file(local_path, "sha256"),
        "sha512": _hash_file(local_path, "sha512"),
        "b2": _hash_file(local_path, "blake2b"),
    }
    if entry.declared_checksum and entry.checksum_algorithm:
        if entry.declared_checksum.upper() == "SKIP":
            entry.checksum_status = "skip"
        else:
            algo_map = {"sha256sums": "sha256", "sha512sums": "sha512", "b2sums": "b2"}
            algo = algo_map.get(entry.checksum_algorithm)
            if algo and entry.calculated_hashes.get(algo):
                entry.checksum_status = (
                    "valid"
                    if entry.calculated_hashes[algo].lower() == entry.declared_checksum.lower()
                    else "invalid"
                )
            elif entry.checksum_algorithm in WEAK_CHECKSUMS:
                entry.checksum_status = "weak"
    elif entry.kind not in {"vcs_git", "vcs_svn", "vcs_mercurial", "vcs_bazaar"}:
        entry.checksum_status = "missing"


def _hash_file(path: Path, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _classify_source_status(entry: SourceEntry, upstream_url: str) -> None:
    if entry.scheme == "http":
        entry.badges.append("HTTP SOURCE")
        entry.risk = "yellow"
    if entry.scheme == "https":
        entry.badges.append("HTTPS")
    if entry.checksum_status == "valid":
        entry.badges.append("CHECKSUM OK")
    elif entry.checksum_status == "skip":
        entry.badges.append("CHECKSUM SKIP")
        if not entry.kind.startswith("vcs_"):
            entry.risk = "yellow"
    elif entry.checksum_status == "invalid":
        entry.badges.append("CHECKSUM INVALID")
        entry.risk = "red"
    elif entry.checksum_status in {"missing", "weak"}:
        entry.badges.append("CHECKSUM WEAK/MISSING")
        entry.risk = "orange"
    if entry.kind.startswith("vcs_") and not re.search(r"[#?](?:commit|tag|revision|branch)=", entry.url):
        entry.badges.append("VCS UNPINNED")
        if entry.risk == "not_verified":
            entry.risk = "yellow"
    if entry.kind == "signature":
        entry.badges.append("PGP SIGNATURE")
        entry.pgp_status = "not_verified"
    if SUSPICIOUS_HOST_RE.search(entry.domain):
        entry.badges.append("TEMP/SHORTENER HOST")
        entry.risk = "red"
    if upstream_url and entry.domain and entry.domain not in _hostish(upstream_url):
        entry.badges.append("DOMAIN DIFFERS")
        if entry.risk == "not_verified":
            entry.risk = "yellow"
    if entry.risk == "not_verified" and entry.checksum_status == "valid" and entry.scheme == "https":
        entry.risk = "green"


def _hostish(url: str) -> str:
    parsed = urlparse(url if re.match(r"^[a-z][a-z0-9+.-]*://", url, re.I) else "https://" + url)
    return parsed.netloc.lower()


def _findings_for_entry(entry: SourceEntry) -> list[Finding]:
    findings: list[Finding] = []
    if entry.scheme == "http":
        findings.append(
            _source_finding(
                "SOURCE_HTTP",
                "REVIEW",
                entry,
                "Source usa HTTP sem TLS.",
                "Prefira HTTPS ou assinatura/checksum upstream independente.",
                classification="CONCRETE_SUSPICION",
                status_impact="YELLOW",
            )
        )
    if entry.checksum_status == "skip":
        if entry.kind.startswith("vcs_"):
            findings.append(
                _source_finding(
                    "SOURCE_CHECKSUM_SKIP_VCS",
                    "INFO",
                    entry,
                    "Checksum SKIP em source VCS.",
                    "Normal em sources VCS; confirme se tag/commit é coerente quando necessário.",
                    classification="OBSERVATION",
                    status_impact="NONE",
                )
            )
        else:
            findings.append(
                _source_finding(
                    "SOURCE_CHECKSUM_SKIP",
                    "REVIEW",
                    entry,
                    "Checksum declarado como SKIP em source não-VCS.",
                    "SKIP reduz integridade local declarada; revise origem e assinatura.",
                    classification="CONCRETE_SUSPICION",
                    status_impact="YELLOW",
                )
            )
    elif entry.checksum_status == "missing":
        findings.append(
            _source_finding(
                "SOURCE_CHECKSUM_MISSING",
                "REVIEW",
                entry,
                "Source sem checksum declarado.",
                "Declare checksum forte quando a fonte nao for VCS.",
                classification="CONCRETE_SUSPICION",
                status_impact="YELLOW",
            )
        )
    elif entry.checksum_status == "weak":
        findings.append(
            _source_finding(
                "SOURCE_CHECKSUM_WEAK",
                "REVIEW",
                entry,
                "Checksum fraco usado.",
                "Prefira sha256sums, sha512sums ou b2sums.",
                classification="CONCRETE_SUSPICION",
                status_impact="YELLOW",
            )
        )
    elif entry.checksum_status == "invalid":
        findings.append(
            _source_finding(
                "SOURCE_CHECKSUM_INVALID",
                "CRITICAL",
                entry,
                "Hash local diverge do checksum declarado.",
                "Nao continue sem entender a divergencia.",
                classification="CONCRETE_FAILURE",
                status_impact="RED",
            )
        )
    if "VCS UNPINNED" in entry.badges:
        findings.append(
            _source_finding(
                "SOURCE_VCS_UNPINNED",
                "INFO",
                entry,
                "Source VCS sem pin claro de commit/tag.",
                "Observação de reprodutibilidade; não é red flag isolada.",
                classification="OBSERVATION",
                status_impact="NONE",
            )
        )
    if "TEMP/SHORTENER HOST" in entry.badges:
        findings.append(
            _source_finding(
                "SOURCE_SUSPICIOUS_HOST",
                "HIGH",
                entry,
                "Source usa encurtador ou hospedagem temporaria.",
                "Prefira dominio oficial do upstream.",
                classification="CONCRETE_SUSPICION",
                status_impact="ORANGE",
            )
        )
    if "DOMAIN DIFFERS" in entry.badges:
        findings.append(
            _source_finding(
                "SOURCE_DOMAIN_DIFFERS",
                "INFO",
                entry,
                "Dominio do source difere de url=.",
                "Confirme se o dominio pertence ao upstream ou mirror oficial.",
                classification="OBSERVATION",
                status_impact="NONE",
            )
        )
    return findings


def _source_finding(
    rule_id: str,
    severity: str,
    entry: SourceEntry,
    description: str,
    recommendation: str,
    classification: str,
    status_impact: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        name="Integridade de source",
        classification=classification,
        severity=severity,
        status_impact=status_impact,
        category="source_integrity",
        file_path="PKGBUILD",
        line_start=None,
        matched_text=entry.raw,
        command=entry.name,
        behavior=description,
        why_it_matters=(
            "Integridade de source é evidência concreta quando checksum/PGP falha ou quando a origem não é verificável."
        ),
        evidence=entry.raw,
        description=description,
        risk_explanation=(
            "Checksum do PKGBUILD confirma integridade local declarada, mas nao prova confianca se source e checksum "
            "foram alterados juntos por um mantenedor malicioso."
        ),
        recommendation=recommendation,
        source="source_integrity",
    )
