from __future__ import annotations

import hashlib
import os
import re
import shlex
from pathlib import Path

from .scan_limits import MAX_TEXT_FILE_BYTES


MAX_TEXT_BYTES = MAX_TEXT_FILE_BYTES
EXCLUDED_DIRS = {
    ".git",
    "pkg",
    "src",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
    ".aur-sentinel-archives",
}
REPORT_FILES = {"audit-report.json", "audit-report.txt", "file-hashes.sha256"}


def is_probably_binary(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            sample = handle.read(4096)
    except OSError:
        return True
    return b"\0" in sample


def iter_regular_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for current_root, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in EXCLUDED_DIRS]
        for filename in filenames:
            path = Path(current_root) / filename
            if path.name in REPORT_FILES:
                continue
            if path.is_file():
                files.append(path)
    return sorted(files)


def iter_text_files(root: Path, max_bytes: int = MAX_TEXT_BYTES) -> list[Path]:
    files: list[Path] = []
    for path in iter_regular_files(root):
        try:
            if path.stat().st_size > max_bytes:
                continue
        except OSError:
            continue
        if not is_probably_binary(path):
            files.append(path)
    return files


def safe_read_text(path: Path, max_bytes: int = MAX_TEXT_BYTES) -> tuple[str, bool]:
    try:
        size = path.stat().st_size
    except OSError:
        return "", False
    truncated = size > max_bytes
    with path.open("rb") as handle:
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        truncated = True
        data = data[:max_bytes]
    return data.decode("utf-8", errors="replace"), truncated


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hash_files(root: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for path in iter_regular_files(root):
        try:
            rel = path.relative_to(root).as_posix()
            hashes[rel] = sha256_file(path)
        except OSError:
            continue
    return dict(sorted(hashes.items()))


def write_hash_file(root: Path, hashes: dict[str, str]) -> Path:
    output = root / "file-hashes.sha256"
    lines = [f"{digest}  {rel}" for rel, digest in sorted(hashes.items())]
    output.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return output


def compare_hashes(root: Path, expected: dict[str, str]) -> tuple[bool, list[str]]:
    current = hash_files(root)
    changes: list[str] = []
    for rel, old_hash in sorted(expected.items()):
        new_hash = current.get(rel)
        if new_hash is None:
            changes.append(f"REMOVED {rel}")
        elif new_hash != old_hash:
            changes.append(f"MODIFIED {rel}")
    for rel in sorted(set(current) - set(expected)):
        changes.append(f"ADDED {rel}")
    return not changes, changes


def classify_file(path: Path) -> str:
    name = path.name
    if name == "PKGBUILD":
        return "PKGBUILD"
    if name == ".SRCINFO":
        return "SRCINFO"
    if name.endswith(".install"):
        return "INSTALL"
    return "AUX"


def strip_inline_comment(line: str) -> tuple[str, str]:
    in_single = False
    in_double = False
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == "'" and not in_double:
            in_single = not in_single
            continue
        if char == '"' and not in_single:
            in_double = not in_double
            continue
        if char == "#" and not in_single and not in_double:
            return line[:index], line[index:]
    return line, ""


def collect_assignments(text: str) -> dict[str, str]:
    assignments: dict[str, str] = {}
    lines = text.splitlines()
    index = 0
    assignment_re = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")
    while index < len(lines):
        line = lines[index]
        stripped_line, _ = strip_inline_comment(line)
        match = assignment_re.match(stripped_line)
        if not match:
            index += 1
            continue
        key, value = match.group(1), match.group(2).strip()
        collected = [value]
        if value.startswith("("):
            balance = value.count("(") - value.count(")")
            while balance > 0 and index + 1 < len(lines):
                index += 1
                next_line, _ = strip_inline_comment(lines[index])
                collected.append(next_line.strip())
                balance += next_line.count("(") - next_line.count(")")
        assignments[key] = " ".join(collected).strip()
        index += 1
    return assignments


def split_assignment_values(value: str) -> list[str]:
    normalized = value.strip()
    if normalized.startswith("(") and normalized.endswith(")"):
        normalized = normalized[1:-1]
    normalized = normalized.replace("\\\n", " ")
    try:
        return [token for token in shlex.split(normalized, comments=True, posix=True) if token]
    except ValueError:
        tokens = re.findall(r"'([^']*)'|\"([^\"]*)\"|([^\s()]+)", normalized)
        return [next(part for part in token if part) for token in tokens]


def parse_pkgbuild_assignments(text: str) -> dict[str, list[str]]:
    parsed: dict[str, list[str]] = {}
    for key, value in collect_assignments(text).items():
        parsed[key] = split_assignment_values(value)
    return parsed


def parse_srcinfo(text: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        result.setdefault(key.strip(), []).append(value.strip())
    return result
