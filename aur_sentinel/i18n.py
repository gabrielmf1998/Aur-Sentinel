from __future__ import annotations

import os
from pathlib import Path

from PySide6.QtCore import QCoreApplication, QLocale, QSettings, QTranslator


LANGUAGE_SETTINGS_KEY = "ui/language"
PT_BR = "pt_BR"
EN_US = "en_US"
SUPPORTED_LANGUAGES = (PT_BR, EN_US)

_translator: QTranslator | None = None
_current_language = PT_BR


def normalize_language(language: object) -> str:
    value = str(language or "").replace("-", "_")
    if value in {"pt", "pt_BR"} or value.startswith("pt_"):
        return PT_BR
    if value in {"en", "en_US"} or value.startswith("en_"):
        return EN_US
    return EN_US


def system_language() -> str:
    return normalize_language(QLocale.system().name())


def initial_language() -> str:
    saved = QSettings().value(LANGUAGE_SETTINGS_KEY, "", str)
    return normalize_language(saved) if saved else system_language()


def current_language() -> str:
    return _current_language


def save_language(language: str) -> None:
    QSettings().setValue(LANGUAGE_SETTINGS_KEY, normalize_language(language))


def translation_directories() -> list[Path]:
    package_root = Path(__file__).resolve().parents[1]
    paths = [
        Path(os.environ["AURSENTINEL_TRANSLATIONS_DIR"])
        for key in ("AURSENTINEL_TRANSLATIONS_DIR",)
        if os.environ.get(key)
    ]
    paths.extend(
        [
            Path.cwd() / "translations",
            Path.cwd() / "build" / "translations",
            package_root / "translations",
            Path(QCoreApplication.applicationDirPath()) / "translations",
            Path("/usr/share/aursentinel/translations"),
        ]
    )

    unique: list[Path] = []
    for path in paths:
        resolved = path.resolve()
        if resolved not in unique:
            unique.append(resolved)
    return unique


def apply_language(language: str, app: QCoreApplication | None = None) -> str:
    global _current_language, _translator

    app = app or QCoreApplication.instance()
    selected = normalize_language(language)
    if app is None:
        _current_language = selected
        return selected

    if _translator is not None:
        app.removeTranslator(_translator)
        _translator = None

    translator = QTranslator(app)
    file_name = f"aursentinel_{selected}.qm"
    for directory in translation_directories():
        candidate = directory / file_name
        if candidate.is_file() and translator.load(str(candidate)):
            app.installTranslator(translator)
            _translator = translator
            break

    _current_language = selected
    return selected
