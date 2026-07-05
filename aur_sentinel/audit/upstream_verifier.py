from __future__ import annotations

import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from .models import Finding
from .source_integrity import SourceEntry


CHECKSUM_ASSET_SUFFIXES = (
    ".sha256",
    ".sha512",
    ".sig",
    ".asc",
    ".sign",
)
CHECKSUM_FILENAMES = (
    "SHA256SUMS",
    "SHA256SUMS.txt",
    "checksums.txt",
    "sha256sums.txt",
)


@dataclass
class UpstreamVerification:
    status: str
    reason: str
    checked_urls: list[str]
    matched_checksum: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason,
            "checked_urls": self.checked_urls,
            "matched_checksum": self.matched_checksum,
        }


def verify_upstream_independent(entry: SourceEntry, timeout: int = 8) -> UpstreamVerification:
    if not entry.url.startswith("https://"):
        return UpstreamVerification("not_available", "Source nao usa HTTPS; verificacao upstream independente nao tentada.", [])
    candidates = _candidate_urls(entry.url)
    checked: list[str] = []
    for url in candidates:
        checked.append(url)
        try:
            payload = _fetch_text(url, timeout)
        except (urllib.error.URLError, TimeoutError, UnicodeDecodeError):
            continue
        checksum = _extract_checksum(payload, entry.name)
        if checksum:
            expected = entry.calculated_hashes.get("sha256") or entry.calculated_hashes.get("sha512")
            if expected and checksum.lower() == expected.lower():
                return UpstreamVerification("confirmed", "Checksum upstream independente confere com arquivo baixado.", checked, checksum)
            return UpstreamVerification("mismatch", "Checksum upstream independente diverge do arquivo baixado.", checked, checksum)
    return UpstreamVerification("not_available", "Nenhum checksum/assinatura upstream independente encontrado por heuristica.", checked)


def apply_upstream_verification(entries: list[SourceEntry], timeout: int = 8) -> list[Finding]:
    findings: list[Finding] = []
    for entry in entries:
        result = verify_upstream_independent(entry, timeout=timeout)
        entry.upstream_status = result.status
        if result.status == "confirmed":
            entry.badges.append("UPSTREAM MATCH")
            if entry.risk == "yellow" and entry.checksum_status == "valid" and entry.scheme == "https":
                entry.risk = "green"
        elif result.status == "mismatch":
            entry.badges.append("UPSTREAM MISMATCH")
            entry.risk = "red"
            findings.append(
                Finding(
                    rule_id="UPSTREAM_CHECKSUM_MISMATCH",
                    name="Checksum upstream independente divergente",
                    severity="CRITICAL",
                    category="source_integrity",
                    file_path="PKGBUILD",
                    matched_text=entry.raw,
                    command=entry.name,
                    description="Checksum obtido de fonte upstream independente diverge do arquivo baixado.",
                    risk_explanation=(
                        "Divergencia entre arquivo baixado e checksum upstream independente pode indicar troca de source, "
                        "espelho comprometido ou metadado AUR incorreto."
                    ),
                    recommendation="Nao continue sem confirmar o release upstream, assinatura e hash oficial.",
                    source="source_integrity",
                )
            )
    return findings


def _candidate_urls(source_url: str) -> list[str]:
    base = source_url.rsplit("/", 1)[0]
    name = source_url.rsplit("/", 1)[-1]
    urls = [source_url + suffix for suffix in CHECKSUM_ASSET_SUFFIXES]
    urls.extend(f"{base}/{filename}" for filename in CHECKSUM_FILENAMES)
    return urls


def _fetch_text(url: str, timeout: int) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "aur-sentinel/0.1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = response.read(256 * 1024)
    return data.decode("utf-8")


def _extract_checksum(text: str, filename: str) -> str | None:
    for line in text.splitlines():
        if filename and filename not in line:
            continue
        match = re.search(r"\b([A-Fa-f0-9]{64}|[A-Fa-f0-9]{128})\b", line)
        if match:
            return match.group(1)
    if len(text.strip()) in {64, 128} and re.fullmatch(r"[A-Fa-f0-9]+", text.strip()):
        return text.strip()
    return None
