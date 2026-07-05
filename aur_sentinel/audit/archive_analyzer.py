from __future__ import annotations

import gzip
import io
import lzma
import os
import re
import shutil
import subprocess
import tarfile
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

from .models import Finding
from .scan_limits import (
    COMMAND_TIMEOUT_SECONDS,
    MAX_ARCHIVE_DEPTH,
    MAX_FILES_SCANNED,
    MAX_TEXT_FILE_BYTES,
    MAX_TOTAL_EXTRACTED_BYTES,
)


ARCHIVE_SUFFIXES = (
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.xz",
    ".tar.zst",
    ".zip",
    ".gz",
    ".xz",
    ".zst",
    ".deb",
    ".rpm",
    ".pkg.tar.zst",
    ".pkg.tar.xz",
    ".pacman",
    ".AppImage",
    ".appimage",
    ".asar",
)


@dataclass
class ArchiveEntry:
    path: str
    kind: str
    size: int
    depth: int
    status: str
    extracted_to: str = ""
    files_extracted: int = 0
    bytes_extracted: int = 0
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "kind": self.kind,
            "size": self.size,
            "depth": self.depth,
            "status": self.status,
            "extracted_to": self.extracted_to,
            "files_extracted": self.files_extracted,
            "bytes_extracted": self.bytes_extracted,
            "message": self.message,
        }


@dataclass
class ArchiveAnalysisReport:
    root: str
    output_dir: str
    archives: list[ArchiveEntry] = field(default_factory=list)
    extracted_roots: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    files_extracted: int = 0
    bytes_extracted: int = 0
    skipped_by_limit: int = 0
    partial: bool = False
    logs: list[str] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, Any]:
        return {
            "archives_seen": len(self.archives),
            "archives_extracted": sum(1 for item in self.archives if item.status == "extracted"),
            "archives_not_analyzed": sum(
                1 for item in self.archives if item.status in {"not_analyzed", "partial", "listed_only"}
            ),
            "files_extracted": self.files_extracted,
            "bytes_extracted": self.bytes_extracted,
            "skipped_by_limit": self.skipped_by_limit,
            "partial": self.partial,
        }

    def to_dict(self) -> dict[str, Any]:
        data = self.summary
        data["root"] = self.root
        data["output_dir"] = self.output_dir
        data["archives"] = [item.to_dict() for item in self.archives]
        data["extracted_roots"] = self.extracted_roots
        data["findings"] = [item.to_dict() for item in self.findings]
        data["logs"] = self.logs[-200:]
        return data


class ArchiveAnalyzer:
    def __init__(
        self,
        max_depth: int = MAX_ARCHIVE_DEPTH,
        max_total_bytes: int = MAX_TOTAL_EXTRACTED_BYTES,
        max_files: int = MAX_FILES_SCANNED,
        timeout_seconds: int = COMMAND_TIMEOUT_SECONDS,
    ) -> None:
        self.max_depth = max_depth
        self.max_total_bytes = max_total_bytes
        self.max_files = max_files
        self.timeout_seconds = timeout_seconds
        self._seen: set[Path] = set()

    def analyze(self, root: Path, output_dir: Path | None = None) -> ArchiveAnalysisReport:
        root = root.resolve()
        output_dir = (output_dir or (root / ".aur-sentinel-archives")).resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        report = ArchiveAnalysisReport(root=str(root), output_dir=str(output_dir))
        self._scan_root(root, output_dir, report, depth=0)
        if report.partial:
            report.findings.append(
                Finding(
                    rule_id="ARCHIVE_ANALYSIS_PARTIAL",
                    name="ANÁLISE PARCIAL: limite atingido",
                    classification="CONCRETE_SUSPICION",
                    severity="REVIEW",
                    status_impact="YELLOW",
                    category="archive_analysis",
                    file_path=str(root),
                    matched_text="ANÁLISE PARCIAL: limite atingido",
                    behavior="A análise de arquivos compactados ficou incompleta por limite ou ferramenta ausente.",
                    why_it_matters="Status verde não deve ser emitido quando etapa crítica ficou incompleta.",
                    evidence="archive_analysis.partial=true",
                    recommendation="Revise manualmente os arquivos não analisados ou aumente limites em ambiente isolado.",
                    source="archive_analysis",
                )
            )
        return report

    def _scan_root(
        self,
        root: Path,
        output_dir: Path,
        report: ArchiveAnalysisReport,
        depth: int,
    ) -> None:
        if depth > self.max_depth:
            report.partial = True
            report.logs.append(f"ANÁLISE PARCIAL: profundidade máxima atingida em {root}")
            return
        for path in _iter_archive_candidates(root, output_dir):
            if len(report.archives) >= self.max_files:
                report.partial = True
                report.skipped_by_limit += 1
                return
            try:
                resolved = path.resolve()
            except OSError:
                continue
            if resolved in self._seen:
                continue
            self._seen.add(resolved)
            entry = self._analyze_archive(path, root, output_dir, report, depth)
            report.archives.append(entry)
            if entry.extracted_to:
                report.extracted_roots.append(entry.extracted_to)
                self._scan_root(Path(entry.extracted_to), output_dir, report, depth + 1)

    def _analyze_archive(
        self,
        path: Path,
        root: Path,
        output_dir: Path,
        report: ArchiveAnalysisReport,
        depth: int,
    ) -> ArchiveEntry:
        rel = _relative(path, root)
        kind = archive_kind(path)
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        dest = _unique_dest(output_dir, rel)
        start_files = report.files_extracted
        start_bytes = report.bytes_extracted
        try:
            if kind in {"tar", "tar.gz", "tgz", "tar.xz", "pkg.tar.xz", "pacman"}:
                status, message = self._extract_tar(path, dest, report)
            elif kind == "zip":
                status, message = self._extract_zip(path, dest, report)
            elif kind == "gz":
                status, message = self._extract_single_stream(path, dest, report, gzip.open, ".gz")
            elif kind == "xz":
                status, message = self._extract_single_stream(path, dest, report, lzma.open, ".xz")
            elif kind in {"tar.zst", "pkg.tar.zst", "zst"}:
                status, message = self._handle_zstd(path, dest, report, kind)
            elif kind == "deb":
                status, message = self._extract_deb(path, dest, report)
            elif kind == "rpm":
                status, message = self._inspect_rpm(path, dest, report)
            elif kind == "appimage":
                status, message = "listed_only", "AppImage identificado; não executado."
            elif kind == "asar":
                status, message = self._inspect_asar(path, dest, report)
            else:
                status, message = "not_analyzed", "Formato não reconhecido."
        except (OSError, tarfile.TarError, zipfile.BadZipFile, EOFError) as exc:
            report.partial = True
            status, message = "partial", f"Erro controlado: {exc}"
        files = report.files_extracted - start_files
        bytes_written = report.bytes_extracted - start_bytes
        extracted_to = str(dest) if files and dest.exists() else ""
        return ArchiveEntry(
            path=rel,
            kind=kind,
            size=size,
            depth=depth,
            status=status,
            extracted_to=extracted_to,
            files_extracted=files,
            bytes_extracted=bytes_written,
            message=message,
        )

    def _extract_tar(
        self,
        path: Path,
        dest: Path,
        report: ArchiveAnalysisReport,
    ) -> tuple[str, str]:
        dest.mkdir(parents=True, exist_ok=True)
        with tarfile.open(path, mode="r:*") as archive:
            for member in archive:
                if not self._can_write_member(member.name, member.size, report):
                    continue
                if member.isdir():
                    _safe_target(dest, member.name).mkdir(parents=True, exist_ok=True)
                    continue
                if member.issym() or member.islnk():
                    report.partial = True
                    report.skipped_by_limit += 1
                    report.logs.append(f"Symlink ignorado em archive: {member.name}")
                    continue
                if not member.isfile():
                    continue
                source = archive.extractfile(member)
                if source is None:
                    continue
                target = _safe_target(dest, member.name)
                self._copy_stream(source, target, int(member.size), report)
        return "partial" if report.partial else "extracted", "Tar extraído com validação de paths."

    def _extract_zip(
        self,
        path: Path,
        dest: Path,
        report: ArchiveAnalysisReport,
    ) -> tuple[str, str]:
        dest.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    if _is_safe_member_name(info.filename):
                        _safe_target(dest, info.filename).mkdir(parents=True, exist_ok=True)
                    continue
                if _zipinfo_is_symlink(info):
                    report.partial = True
                    report.skipped_by_limit += 1
                    report.logs.append(f"Symlink ignorado em zip: {info.filename}")
                    continue
                if not self._can_write_member(info.filename, info.file_size, report):
                    continue
                with archive.open(info) as source:
                    target = _safe_target(dest, info.filename)
                    self._copy_stream(source, target, int(info.file_size), report)
        return "partial" if report.partial else "extracted", "Zip extraído com validação de paths."

    def _extract_single_stream(
        self,
        path: Path,
        dest: Path,
        report: ArchiveAnalysisReport,
        opener: Any,
        suffix: str,
    ) -> tuple[str, str]:
        dest.mkdir(parents=True, exist_ok=True)
        name = path.name[: -len(suffix)] if path.name.lower().endswith(suffix) else path.stem
        if not name:
            name = path.stem or "decompressed"
        if not self._can_write_member(name, path.stat().st_size, report):
            return "partial", "Limite atingido antes da extração."
        target = _safe_target(dest, name)
        with opener(path, "rb") as source:
            self._copy_stream(source, target, None, report)
        return "partial" if report.partial else "extracted", f"{suffix} descompactado sem executar conteúdo."

    def _handle_zstd(
        self,
        path: Path,
        dest: Path,
        report: ArchiveAnalysisReport,
        kind: str,
    ) -> tuple[str, str]:
        if kind in {"tar.zst", "pkg.tar.zst"} and shutil.which("tar"):
            listed = self._run_command(["tar", "-tf", str(path)])
            if listed.returncode != 0:
                report.partial = True
                return "not_analyzed", "tar não conseguiu listar zstd."
            names = listed.stdout.splitlines()
            if any(not _is_safe_member_name(name) for name in names):
                report.partial = True
                return "partial", "Path traversal bloqueado em tar.zst."
            report.partial = True
            return "listed_only", "tar.zst listado com segurança; extração externa não foi usada."
        if kind == "zst" and shutil.which("zstd"):
            dest.mkdir(parents=True, exist_ok=True)
            output_name = path.name[:-4] if path.name.lower().endswith(".zst") else path.stem
            target = _safe_target(dest, output_name)
            completed = self._run_command(["zstd", "-dc", str(path)], stdout_path=target)
            if completed.returncode == 0:
                try:
                    report.files_extracted += 1
                    report.bytes_extracted += target.stat().st_size
                except OSError:
                    pass
                return "extracted", "zst descompactado via zstd com timeout."
            report.partial = True
            return "partial", "Falha ao descompactar zst."
        report.partial = True
        return "not_analyzed", "Ferramenta zstd/tar compatível não disponível."

    def _extract_deb(
        self,
        path: Path,
        dest: Path,
        report: ArchiveAnalysisReport,
    ) -> tuple[str, str]:
        dest.mkdir(parents=True, exist_ok=True)
        try:
            members = _read_ar_members(path)
        except OSError as exc:
            report.partial = True
            return "partial", f"Falha lendo deb/ar: {exc}"
        extracted = 0
        for name, data in members:
            if not _is_safe_member_name(name):
                report.partial = True
                continue
            if not name.startswith(("control.tar", "data.tar")):
                continue
            if not self._can_write_member(name, len(data), report):
                continue
            target = _safe_target(dest, name)
            self._copy_stream(io.BytesIO(data), target, len(data), report)
            extracted += 1
        if extracted:
            return "extracted", "deb/ar extraído parcialmente para tarballs internos."
        report.partial = True
        return "not_analyzed", "deb sem tarballs internos legíveis."

    def _inspect_rpm(
        self,
        path: Path,
        dest: Path,
        report: ArchiveAnalysisReport,
    ) -> tuple[str, str]:
        if shutil.which("rpm"):
            completed = self._run_command(["rpm", "-qp", "--scripts", str(path)])
            if completed.returncode == 0 and completed.stdout.strip():
                dest.mkdir(parents=True, exist_ok=True)
                target = dest / "rpm-scriptlets.txt"
                _safe_write_text(target, completed.stdout[:MAX_TEXT_FILE_BYTES])
                report.files_extracted += 1
                report.bytes_extracted += target.stat().st_size
                return "listed_only", "RPM scriptlets coletados sem instalar."
        report.partial = True
        return "not_analyzed", "rpm não disponível ou sem scriptlets legíveis."

    def _inspect_asar(
        self,
        path: Path,
        dest: Path,
        report: ArchiveAnalysisReport,
    ) -> tuple[str, str]:
        tool = shutil.which("asar")
        if not tool:
            return "not_analyzed", ".asar não analisado: ferramenta asar indisponível."
        completed = self._run_command([tool, "list", str(path)])
        if completed.returncode != 0:
            report.partial = True
            return "partial", ".asar não pôde ser listado."
        dest.mkdir(parents=True, exist_ok=True)
        target = dest / "asar-file-list.txt"
        _safe_write_text(target, completed.stdout[:MAX_TEXT_FILE_BYTES])
        report.files_extracted += 1
        report.bytes_extracted += target.stat().st_size
        return "listed_only", ".asar listado sem executar conteúdo."

    def _can_write_member(self, name: str, size: int | None, report: ArchiveAnalysisReport) -> bool:
        if not _is_safe_member_name(name):
            report.partial = True
            report.skipped_by_limit += 1
            report.logs.append(f"Path traversal bloqueado: {name}")
            return False
        if report.files_extracted >= self.max_files:
            report.partial = True
            report.skipped_by_limit += 1
            return False
        if size is not None and report.bytes_extracted + max(0, size) > self.max_total_bytes:
            report.partial = True
            report.skipped_by_limit += 1
            return False
        return True

    def _copy_stream(
        self,
        source: BinaryIO,
        target: Path,
        expected_size: int | None,
        report: ArchiveAnalysisReport,
    ) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        started = time.monotonic()
        with target.open("wb") as output:
            while True:
                if time.monotonic() - started > self.timeout_seconds:
                    report.partial = True
                    report.skipped_by_limit += 1
                    break
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                if report.bytes_extracted + len(chunk) > self.max_total_bytes:
                    report.partial = True
                    report.skipped_by_limit += 1
                    break
                output.write(chunk)
                written += len(chunk)
                report.bytes_extracted += len(chunk)
        if expected_size is not None and written < expected_size:
            report.partial = True
        report.files_extracted += 1

    def _run_command(self, args: list[str], stdout_path: Path | None = None) -> subprocess.CompletedProcess[str]:
        stdout: int | Any = subprocess.PIPE
        handle = None
        try:
            if stdout_path is not None:
                stdout_path.parent.mkdir(parents=True, exist_ok=True)
                handle = stdout_path.open("wb")
                stdout = handle
            return subprocess.run(
                args,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=subprocess.PIPE,
                timeout=self.timeout_seconds,
                check=False,
                text=stdout_path is None,
                errors="replace",
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return subprocess.CompletedProcess(args, 124, "", str(exc))
        finally:
            if handle is not None:
                handle.close()


def analyze_archives(root: Path, output_dir: Path | None = None) -> ArchiveAnalysisReport:
    return ArchiveAnalyzer().analyze(root, output_dir)


def archive_kind(path: Path) -> str:
    name = path.name.lower()
    for suffix, kind in (
        (".pkg.tar.zst", "pkg.tar.zst"),
        (".pkg.tar.xz", "pkg.tar.xz"),
        (".tar.gz", "tar.gz"),
        (".tgz", "tgz"),
        (".tar.xz", "tar.xz"),
        (".tar.zst", "tar.zst"),
        (".appimage", "appimage"),
        (".pacman", "pacman"),
        (".asar", "asar"),
        (".zip", "zip"),
        (".deb", "deb"),
        (".rpm", "rpm"),
        (".tar", "tar"),
        (".gz", "gz"),
        (".xz", "xz"),
        (".zst", "zst"),
    ):
        if name.endswith(suffix):
            return kind
    return "unknown"


def is_archive(path: Path) -> bool:
    return archive_kind(path) != "unknown"


def _iter_archive_candidates(root: Path, output_dir: Path) -> list[Path]:
    candidates: list[Path] = []
    for current_root, dirnames, filenames in os.walk(root, followlinks=False):
        current_path = Path(current_root)
        if output_dir in current_path.parents or current_path == output_dir:
            dirnames[:] = []
            continue
        dirnames[:] = [
            name
            for name in dirnames
            if name not in {".git", "__pycache__", ".venv", "venv", "node_modules"}
        ]
        for filename in filenames:
            path = current_path / filename
            if path.is_symlink():
                continue
            if path.is_file() and is_archive(path):
                candidates.append(path)
    return sorted(candidates)


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


def _unique_dest(output_dir: Path, rel: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", rel).strip("_") or "archive"
    dest = output_dir / safe
    if not dest.exists():
        return dest
    index = 1
    while True:
        candidate = output_dir / f"{safe}.{index}"
        if not candidate.exists():
            return candidate
        index += 1


def _is_safe_member_name(name: str) -> bool:
    normalized = name.replace("\\", "/")
    if not normalized or normalized.startswith("/"):
        return False
    if re.match(r"^[A-Za-z]:/", normalized):
        return False
    parts = PurePosixPath(normalized).parts
    return all(part not in {"..", ""} for part in parts)


def _safe_target(dest: Path, member_name: str) -> Path:
    if not _is_safe_member_name(member_name):
        raise OSError(f"unsafe archive path: {member_name}")
    target = (dest / member_name).resolve()
    root = dest.resolve()
    if target != root and root not in target.parents:
        raise OSError(f"archive path escapes destination: {member_name}")
    return target


def _zipinfo_is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = info.external_attr >> 16
    return (mode & 0o170000) == 0o120000


def _safe_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", errors="replace")


def _read_ar_members(path: Path) -> list[tuple[str, bytes]]:
    data = path.read_bytes()
    if not data.startswith(b"!<arch>\n"):
        return []
    offset = 8
    members: list[tuple[str, bytes]] = []
    while offset + 60 <= len(data):
        header = data[offset : offset + 60]
        offset += 60
        name = header[:16].decode("utf-8", errors="replace").strip().rstrip("/")
        try:
            size = int(header[48:58].decode("ascii", errors="replace").strip())
        except ValueError:
            break
        payload = data[offset : offset + size]
        members.append((name, payload))
        offset += size + (size % 2)
    return members
