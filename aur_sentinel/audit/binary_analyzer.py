from __future__ import annotations

import hashlib
import os
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Finding
from .scan_limits import COMMAND_TIMEOUT_SECONDS, MAX_BINARY_STRINGS_BYTES


SUSPICIOUS_STRINGS = (
    "/etc/systemd/system",
    "~/.config/systemd/user",
    "/sys/fs/bpf",
    "bpf_map",
    "bpf_object__load",
    "bpf_program__attach",
    "bpf_map__pin",
    "hidden_pids",
    "hidden_names",
    ".ssh",
    "known_hosts",
    "id_rsa",
    "github",
    "npmrc",
    "_authToken",
    "Vault",
    "SLACK",
    "discord",
    "telegram",
    "cookies",
    "Login Data",
    "POST /upload",
    "multipart/form-data",
    "onion",
    "tor",
    "PTRACE_ATTACH",
    "LD_PRELOAD",
    "/etc/ld.so.preload",
)


@dataclass
class BinaryInfo:
    path: str
    kind: str
    size: int
    executable: bool
    sha256: str
    file_output: str = ""
    suspicious_strings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "kind": self.kind,
            "size": self.size,
            "executable": self.executable,
            "sha256": self.sha256,
            "file_output": self.file_output,
            "suspicious_strings": self.suspicious_strings,
        }


def analyze_binary(path: Path, root: Path | None = None) -> tuple[BinaryInfo | None, list[Finding]]:
    kind = detect_binary_kind(path)
    executable = _is_executable(path)
    if kind == "unknown" and not executable:
        return None, []
    rel = path.relative_to(root).as_posix() if root else path.as_posix()
    info = BinaryInfo(
        path=rel,
        kind=kind,
        size=path.stat().st_size,
        executable=executable,
        sha256=_sha256(path),
        file_output=_file_output(path),
        suspicious_strings=_suspicious_strings(path),
    )
    findings: list[Finding] = []
    findings.append(
        Finding(
            rule_id="BINARY_FOUND",
            name="Arquivo binario encontrado",
            classification="OBSERVATION",
            severity="INFO",
            status_impact="NONE",
            category="binary",
            file_path=rel,
            matched_text=f"{kind} sha256={info.sha256}",
            command=None,
            behavior="Arquivo binário ou executável encontrado nos sources extraídos.",
            why_it_matters="Binários em pacotes -bin/prebuilt são esperados; o achado não prova risco sem acionamento por script ou origem divergente.",
            evidence=f"{kind} sha256={info.sha256}",
            description="Arquivo binario ou executavel encontrado nos sources extraidos.",
            risk_explanation="Binarios baixados podem conter payload nao revisavel como texto; este achado nao executa o binario.",
            recommendation="Revise origem, assinatura, hash upstream e strings suspeitas antes de confiar no artefato.",
            source="binary",
        )
    )
    if info.suspicious_strings:
        findings.append(
            Finding(
                rule_id="BINARY_SUSPICIOUS_STRINGS",
                name="Strings suspeitas em binario",
                classification="OBSERVATION",
                severity="INFO",
                status_impact="NONE",
                category="binary",
                file_path=rel,
                matched_text=", ".join(info.suspicious_strings[:12]),
                command=None,
                behavior="Binário contém strings sensíveis, mas não foi observada execução ou exfiltração concreta.",
                why_it_matters="Strings ajudam revisão manual, mas não devem gerar HIGH isoladamente em pacote prebuilt.",
                evidence=", ".join(info.suspicious_strings[:12]),
                description="Binario contem strings associadas a persistencia, credenciais, eBPF, upload ou ocultacao.",
                risk_explanation="Strings nao provam intencao maliciosa, mas indicam necessidade de engenharia reversa/revisao manual.",
                recommendation="Confirme se as strings sao esperadas para o upstream e revise o binario com ferramentas apropriadas.",
                source="binary",
            )
        )
    return info, findings


def detect_binary_kind(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            data = handle.read(16)
    except OSError:
        return "unknown"
    if data.startswith(b"\x7fELF"):
        return "ELF"
    if data.startswith(b"MZ"):
        return "PE/Windows"
    if data[:4] in {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe"}:
        return "Mach-O"
    if data.startswith(b"PK\x03\x04") and path.suffix.lower() == ".jar":
        return "JAR"
    if path.suffix.lower() in {".so", ".a", ".appimage"}:
        return path.suffix.lower().lstrip(".").upper()
    return "unknown"


def _is_executable(path: Path) -> bool:
    try:
        return bool(path.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    except OSError:
        return False


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _file_output(path: Path) -> str:
    try:
        completed = subprocess.run(
            ["file", "--brief", str(path)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=min(10, COMMAND_TIMEOUT_SECONDS),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout.strip()


def _suspicious_strings(path: Path, limit_bytes: int = MAX_BINARY_STRINGS_BYTES) -> list[str]:
    remaining = limit_bytes
    found: set[str] = set()
    needles = {item: item.lower() for item in SUSPICIOUS_STRINGS}
    tail = ""
    try:
        with path.open("rb") as handle:
            while remaining > 0:
                chunk = handle.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                text = tail + chunk.decode("latin1", errors="ignore").lower()
                for original, lower in needles.items():
                    if lower in text:
                        found.add(original)
                tail = text[-512:]
    except OSError:
        return []
    return sorted(set(found))
