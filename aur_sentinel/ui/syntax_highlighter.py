from __future__ import annotations

import re

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QSyntaxHighlighter, QTextCharFormat


PALETTE = {
    "keyword": "#3b82f6",
    "string": "#16a34a",
    "comment": "#6b7280",
    "variable": "#0891b2",
    "command_suspicious": "#d97706",
    "command_critical": "#dc2626",
    "function": "#7c3aed",
    "section": "#2563eb",
    "diff_added": "#15803d",
    "diff_removed": "#b91c1c",
    "diff_header": "#7c3aed",
    "log_error": "#dc2626",
    "log_warning": "#d97706",
    "log_success": "#16a34a",
    "log_info": "#2563eb",
    "path": "#0891b2",
}

CRITICAL_PATTERNS = [
    r"curl\b[^|]*\|\s*bash\b",
    r"wget\b[^|]*\|\s*sh\b",
    r"\beval\b",
    r"\bbase64\s+-d\b",
    r"\b(?:sudo|su|doas|pkexec)\b",
    r"\bsystemctl\s+(?:enable|start)\b",
    r"\buseradd\b",
    r"\bchmod\s+(?:4755|u\+s)\b",
    r"\bsetcap\b",
    r"\bpacman-key\b",
    r"/etc/pacman\.conf",
    r"/etc/pacman\.d/mirrorlist",
    r"\brm\s+-[A-Za-z]*r[A-Za-z]*f[A-Za-z]*\s+/",
    r"\brm\s+-[A-Za-z]*r[A-Za-z]*f[A-Za-z]*\s+['\"]?\$HOME['\"]?",
    r"\bmkfs(?:\.[A-Za-z0-9_-]+)?\b",
    r"\bwipefs\b",
    r"\bdd\s+if=/dev/zero\b",
]

SUSPICIOUS_PATTERNS = [
    r"\bnpm\s+(?:install|ci|run)\b",
    r"\bnpx\b",
    r"\bbun\s+install\b",
    r"\bbunx\b",
    r"\bpnpm\s+(?:install|dlx)\b",
    r"\byarn\b",
    r"\bpip\s+install\b",
    r"\bcargo\s+(?:build|install)\b",
    r"\bgo\s+(?:get|install|mod\s+download|generate)\b",
    r"\bcomposer\s+(?:install|update)\b",
    r"\bmvn\b",
    r"\bgradle\b",
    r"(^|\s)\./gradlew\b",
]

INFO_PATTERNS = [
    r"\bsource\s*=",
    r"\b(?:sha256sums|b2sums|validpgpkeys|depends|makedepends)\s*=",
    r"\b(?:prepare|build|check|package|pkgver)\s*\(\)",
]


def fmt(color: str, bold: bool = False, italic: bool = False) -> QTextCharFormat:
    text_format = QTextCharFormat()
    text_format.setForeground(QColor(color))
    if bold:
        text_format.setFontWeight(QFont.Bold)
    if italic:
        text_format.setFontItalic(True)
    return text_format


class RegexHighlighter(QSyntaxHighlighter):
    def __init__(self, document) -> None:
        super().__init__(document)
        self.rules: list[tuple[re.Pattern[str], QTextCharFormat]] = []

    def highlightBlock(self, text: str) -> None:  # noqa: N802
        for pattern, text_format in self.rules:
            for match in pattern.finditer(text):
                start = match.start(0)
                length = max(1, match.end(0) - start)
                self.setFormat(start, length, text_format)


class BashHighlighter(RegexHighlighter):
    def __init__(self, document) -> None:
        super().__init__(document)
        self.rules = [
            (re.compile(r"#.*$"), fmt(PALETTE["comment"], italic=True)),
            (re.compile(r"(['\"])(?:\\.|(?!\1).)*\1"), fmt(PALETTE["string"])),
            (re.compile(r"\$[{]?[A-Za-z_][A-Za-z0-9_]*[}]?"), fmt(PALETTE["variable"])),
            (re.compile(r"\b(?:if|then|else|elif|fi|for|while|do|done|case|esac|function|return|local|export)\b"), fmt(PALETTE["keyword"], bold=True)),
            (re.compile(r"^\s*(?:prepare|build|check|package|pkgver)[\w@._+-]*\s*\(\)"), fmt(PALETTE["function"], bold=True)),
            *[(re.compile(pattern, re.IGNORECASE), fmt(PALETTE["command_suspicious"], bold=True)) for pattern in SUSPICIOUS_PATTERNS],
            *[(re.compile(pattern, re.IGNORECASE), fmt(PALETTE["command_critical"], bold=True)) for pattern in CRITICAL_PATTERNS],
            *[(re.compile(pattern, re.IGNORECASE), fmt(PALETTE["log_info"], bold=True)) for pattern in INFO_PATTERNS],
        ]


class SrcInfoHighlighter(RegexHighlighter):
    def __init__(self, document) -> None:
        super().__init__(document)
        self.rules = [
            (re.compile(r"^\s*(pkgbase|pkgname)\s*=.*$"), fmt(PALETTE["section"], bold=True)),
            (re.compile(r"^\s*[A-Za-z0-9_+-]+\s*="), fmt(PALETTE["keyword"], bold=True)),
            (re.compile(r"#.*$"), fmt(PALETTE["comment"], italic=True)),
            *[(re.compile(pattern, re.IGNORECASE), fmt(PALETTE["command_critical"], bold=True)) for pattern in CRITICAL_PATTERNS],
            *[(re.compile(pattern, re.IGNORECASE), fmt(PALETTE["command_suspicious"], bold=True)) for pattern in SUSPICIOUS_PATTERNS],
        ]


class DiffHighlighter(RegexHighlighter):
    def highlightBlock(self, text: str) -> None:  # noqa: N802
        if text.startswith(("diff --git", "index ", "@@")):
            self.setFormat(0, len(text), fmt(PALETTE["diff_header"], bold=True))
        elif text.startswith("+") and not text.startswith("+++"):
            self.setFormat(0, len(text), fmt(PALETTE["diff_added"]))
        elif text.startswith("-") and not text.startswith("---"):
            self.setFormat(0, len(text), fmt(PALETTE["diff_removed"]))
        for pattern in CRITICAL_PATTERNS:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                self.setFormat(match.start(), match.end() - match.start(), fmt(PALETTE["command_critical"], bold=True))
        for pattern in SUSPICIOUS_PATTERNS:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                self.setFormat(match.start(), match.end() - match.start(), fmt(PALETTE["command_suspicious"], bold=True))


class LogHighlighter(RegexHighlighter):
    def highlightBlock(self, text: str) -> None:  # noqa: N802
        lower = text.lower()
        if any(word in lower for word in ("error", "falhou", "failed", "critical")):
            self.setFormat(0, len(text), fmt(PALETTE["log_error"], bold=True))
        elif any(word in lower for word in ("warning", "aviso", "red flag", "atencao")):
            self.setFormat(0, len(text), fmt(PALETTE["log_warning"], bold=True))
        elif any(word in lower for word in ("ok", "sucesso", "concluido", "success")):
            self.setFormat(0, len(text), fmt(PALETTE["log_success"], bold=True))
        elif any(word in lower for word in ("info", "==", "::")):
            self.setFormat(0, len(text), fmt(PALETTE["log_info"]))
        for match in re.finditer(r"(?:/[\w@._+ -]+)+", text):
            self.setFormat(match.start(), match.end() - match.start(), fmt(PALETTE["path"]))
        for pattern in CRITICAL_PATTERNS:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                self.setFormat(match.start(), match.end() - match.start(), fmt(PALETTE["command_critical"], bold=True))


class JsonHighlighter(RegexHighlighter):
    def __init__(self, document) -> None:
        super().__init__(document)
        self.rules = [
            (re.compile(r'"[^"]*"\s*:'), fmt(PALETTE["keyword"], bold=True)),
            (re.compile(r':\s*"[^"]*"'), fmt(PALETTE["string"])),
            (re.compile(r"\b(?:true|false|null)\b"), fmt(PALETTE["section"], bold=True)),
            (re.compile(r"-?\b\d+(?:\.\d+)?\b"), fmt(PALETTE["variable"])),
        ]


class TextReportHighlighter(LogHighlighter):
    pass


def make_highlighter(kind: str, document) -> QSyntaxHighlighter:
    if kind in {"bash", "pkgbuild", "install", "sh"}:
        return BashHighlighter(document)
    if kind == "srcinfo":
        return SrcInfoHighlighter(document)
    if kind == "diff":
        return DiffHighlighter(document)
    if kind == "log":
        return LogHighlighter(document)
    if kind == "json":
        return JsonHighlighter(document)
    if kind in {"txt", "report"}:
        return TextReportHighlighter(document)
    return BashHighlighter(document)
