from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from PySide6.QtCore import QRect, QSize, Qt, Signal
from PySide6.QtGui import (
    QColor,
    QFont,
    QKeySequence,
    QPainter,
    QShortcut,
    QTextCharFormat,
    QTextCursor,
    QTextFormat,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QStyle,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from aur_sentinel.audit.ai_bundle import create_ai_review_bundle
from aur_sentinel.audit.file_audit import is_probably_binary, safe_read_text
from aur_sentinel.audit.models import AuditReport, Finding
from aur_sentinel.audit.scan_limits import MAX_FILE_PREVIEW_BYTES, MAX_UI_LOG_LINES
from aur_sentinel.ui.risk_visuals import (
    status_for_install_status,
    status_for_source_risk,
)
from aur_sentinel.ui.syntax_highlighter import make_highlighter
from aur_sentinel.utils.timefmt import format_unix_timestamp


SEVERITY_COLORS = {
    "INFO": QColor("#6b7280"),
    "LOW": QColor("#3b82f6"),
    "OBSERVATION": QColor("#64748b"),
    "REVIEW": QColor("#ca8a04"),
    "MEDIUM": QColor("#d97706"),
    "HIGH": QColor("#dc2626"),
    "CRITICAL": QColor("#7f1d1d"),
}

CLASSIFICATION_LABELS = {
    "CONCRETE_FAILURE": "CRÍTICO",
    "CONCRETE_SUSPICION": "SUSPEITO",
    "OBSERVATION": "Observação",
    "INFO": "Info",
}

CLASSIFICATION_COLORS = {
    "CONCRETE_FAILURE": QColor("#dc2626"),
    "CONCRETE_SUSPICION": QColor("#f59e0b"),
    "OBSERVATION": QColor("#64748b"),
    "INFO": QColor("#6b7280"),
}


class LineNumberArea(QWidget):
    def __init__(self, editor: "LineNumberedTextEdit") -> None:
        super().__init__(editor)
        self.editor = editor

    def sizeHint(self) -> QSize:
        return QSize(self.editor.line_number_area_width(), 0)

    def paintEvent(self, event) -> None:  # type: ignore[override]
        self.editor.line_number_area_paint_event(event)


class LineNumberedTextEdit(QPlainTextEdit):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.line_number_area = LineNumberArea(self)
        self._search_selections: list[QTextEdit.ExtraSelection] = []
        self._range_selection: QTextEdit.ExtraSelection | None = None
        self.blockCountChanged.connect(self.update_line_number_area_width)
        self.updateRequest.connect(self.update_line_number_area)
        self.cursorPositionChanged.connect(self.highlight_current_line)
        self.update_line_number_area_width(0)
        self.highlight_current_line()
        self.setReadOnly(True)
        font = QFont("monospace")
        font.setStyleHint(QFont.Monospace)
        self.setFont(font)
        self.setLineWrapMode(QPlainTextEdit.NoWrap)

    def line_number_area_width(self) -> int:
        digits = len(str(max(1, self.blockCount())))
        return 12 + self.fontMetrics().horizontalAdvance("9") * digits

    def update_line_number_area_width(self, _new_block_count: int) -> None:
        self.setViewportMargins(self.line_number_area_width(), 0, 0, 0)

    def update_line_number_area(self, rect: QRect, dy: int) -> None:
        if dy:
            self.line_number_area.scroll(0, dy)
        else:
            self.line_number_area.update(0, rect.y(), self.line_number_area.width(), rect.height())
        if rect.contains(self.viewport().rect()):
            self.update_line_number_area_width(0)

    def resizeEvent(self, event) -> None:  # type: ignore[override]
        super().resizeEvent(event)
        contents_rect = self.contentsRect()
        self.line_number_area.setGeometry(
            QRect(contents_rect.left(), contents_rect.top(), self.line_number_area_width(), contents_rect.height())
        )

    def line_number_area_paint_event(self, event) -> None:
        painter = QPainter(self.line_number_area)
        painter.fillRect(event.rect(), self.palette().alternateBase())
        block = self.firstVisibleBlock()
        block_number = block.blockNumber()
        top = int(self.blockBoundingGeometry(block).translated(self.contentOffset()).top())
        bottom = top + int(self.blockBoundingRect(block).height())
        while block.isValid() and top <= event.rect().bottom():
            if block.isVisible() and bottom >= event.rect().top():
                number = str(block_number + 1)
                painter.setPen(self.palette().text().color())
                painter.drawText(
                    0,
                    top,
                    self.line_number_area.width() - 4,
                    self.fontMetrics().height(),
                    Qt.AlignRight,
                    number,
                )
            block = block.next()
            top = bottom
            bottom = top + int(self.blockBoundingRect(block).height())
            block_number += 1

    def highlight_current_line(self) -> None:
        selection = QTextEdit.ExtraSelection()
        selection.format.setBackground(self.palette().alternateBase())
        selection.format.setProperty(QTextFormat.FullWidthSelection, True)
        selection.cursor = self.textCursor()
        selection.cursor.clearSelection()
        self._refresh_extra_selections(selection)

    def _refresh_extra_selections(self, current_line: QTextEdit.ExtraSelection | None = None) -> None:
        selections: list[QTextEdit.ExtraSelection] = []
        if current_line is not None:
            selections.append(current_line)
        selections.extend(self._search_selections)
        if self._range_selection is not None:
            selections.append(self._range_selection)
        self.setExtraSelections(selections)

    def set_search_selections(self, selections: list[QTextEdit.ExtraSelection]) -> None:
        self._search_selections = selections
        self.highlight_current_line()

    def clear_focus_range(self) -> None:
        self._range_selection = None
        self.highlight_current_line()

    def goto_line(self, line_number: int | None, line_end: int | None = None) -> None:
        if not line_number:
            return
        block = self.document().findBlockByLineNumber(max(0, line_number - 1))
        if not block.isValid():
            return
        cursor = QTextCursor(block)
        if line_end and line_end > line_number:
            end_block = self.document().findBlockByLineNumber(max(0, line_end - 1))
            if end_block.isValid():
                cursor.setPosition(block.position())
                cursor.setPosition(end_block.position() + end_block.length() - 1, QTextCursor.KeepAnchor)
        self.setTextCursor(cursor)
        self._highlight_line_range(line_number, line_end or line_number)
        self.centerCursor()
        self.setFocus(Qt.OtherFocusReason)

    def _highlight_line_range(self, line_start: int, line_end: int) -> None:
        start_block = self.document().findBlockByLineNumber(max(0, line_start - 1))
        end_block = self.document().findBlockByLineNumber(max(0, line_end - 1))
        if not start_block.isValid() or not end_block.isValid():
            return
        selection = QTextEdit.ExtraSelection()
        selection.format.setBackground(QColor("#fbbf24"))
        selection.cursor = QTextCursor(start_block)
        selection.cursor.setPosition(
            end_block.position() + max(0, end_block.length() - 1),
            QTextCursor.KeepAnchor,
        )
        self._range_selection = selection
        self.highlight_current_line()


class SearchableTextViewer(QWidget):
    def __init__(self, highlighter_kind: str = "bash", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.editor = LineNumberedTextEdit()
        self._highlighter = None
        self._highlighter_kind = highlighter_kind
        self._matches: list[tuple[int, int]] = []
        self._current_match = -1
        self._build_ui()
        self.set_highlighter(highlighter_kind)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Pesquisar no arquivo")
        self.search_button = QPushButton("Buscar")
        self.search_button.setIcon(self.style().standardIcon(QStyle.SP_FileDialogContentsView))
        self.prev_button = QPushButton("Anterior")
        self.next_button = QPushButton("Proximo")
        self.case_check = QCheckBox("Aa")
        self.case_check.setToolTip("Alternar busca case-sensitive")
        self.counter_label = QLabel("0/0")
        self.counter_label.setMinimumWidth(52)
        self.counter_label.setAlignment(Qt.AlignCenter)

        row.addWidget(self.search_edit, 1)
        row.addWidget(self.search_button)
        row.addWidget(self.prev_button)
        row.addWidget(self.next_button)
        row.addWidget(self.case_check)
        row.addWidget(self.counter_label)
        layout.addLayout(row)
        layout.addWidget(self.editor, 1)

        self.search_edit.textChanged.connect(self._rebuild_matches)
        self.search_button.clicked.connect(self._rebuild_matches)
        self.prev_button.clicked.connect(self.previous_match)
        self.next_button.clicked.connect(self.next_match)
        self.case_check.toggled.connect(self._rebuild_matches)
        self._find_shortcut = QShortcut(QKeySequence.Find, self)
        self._find_shortcut.activated.connect(self.focus_search)

    def setPlainText(self, text: str) -> None:
        self.editor.setPlainText(text)
        self._rebuild_matches()

    def clear(self) -> None:
        self.setPlainText("")

    def set_highlighter(self, kind: str) -> None:
        self._highlighter_kind = kind
        self._highlighter = make_highlighter(kind, self.editor.document())

    def toPlainText(self) -> str:
        return self.editor.toPlainText()

    def textCursor(self) -> QTextCursor:
        return self.editor.textCursor()

    def setTextCursor(self, cursor: QTextCursor) -> None:
        self.editor.setTextCursor(cursor)

    def ensureCursorVisible(self) -> None:
        self.editor.ensureCursorVisible()

    def goto_line(self, line_number: int | None, line_end: int | None = None) -> None:
        self.editor.goto_line(line_number, line_end)

    def setFocus(self, reason: Qt.FocusReason = Qt.OtherFocusReason) -> None:  # type: ignore[override]
        self.editor.setFocus(reason)

    def focus_search(self) -> None:
        self.search_edit.setFocus(Qt.ShortcutFocusReason)
        self.search_edit.selectAll()

    def _rebuild_matches(self) -> None:
        query = self.search_edit.text()
        self._matches = []
        self._current_match = -1
        self.editor.clear_focus_range()
        if not query:
            self.editor.set_search_selections([])
            self._update_counter()
            return

        text = self.editor.toPlainText()
        haystack = text if self.case_check.isChecked() else text.lower()
        needle = query if self.case_check.isChecked() else query.lower()
        start = 0
        while True:
            index = haystack.find(needle, start)
            if index < 0:
                break
            self._matches.append((index, index + len(query)))
            start = index + max(1, len(query))
        self._current_match = 0 if self._matches else -1
        self._apply_search_highlights()
        self._goto_current_match()
        self._update_counter()

    def _apply_search_highlights(self) -> None:
        selections: list[QTextEdit.ExtraSelection] = []
        for idx, (start, end) in enumerate(self._matches):
            selection = QTextEdit.ExtraSelection()
            fmt = QTextCharFormat()
            fmt.setBackground(QColor("#fde68a") if idx != self._current_match else QColor("#f97316"))
            fmt.setForeground(QColor("#111827") if idx == self._current_match else QColor("#111827"))
            selection.format = fmt
            cursor = QTextCursor(self.editor.document())
            cursor.setPosition(start)
            cursor.setPosition(end, QTextCursor.KeepAnchor)
            selection.cursor = cursor
            selections.append(selection)
        self.editor.set_search_selections(selections)

    def _goto_current_match(self) -> None:
        if self._current_match < 0 or self._current_match >= len(self._matches):
            return
        start, end = self._matches[self._current_match]
        cursor = QTextCursor(self.editor.document())
        cursor.setPosition(start)
        cursor.setPosition(end, QTextCursor.KeepAnchor)
        self.editor.setTextCursor(cursor)
        self.editor.centerCursor()

    def next_match(self) -> None:
        if not self._matches:
            return
        self._current_match = (self._current_match + 1) % len(self._matches)
        self._apply_search_highlights()
        self._goto_current_match()
        self._update_counter()

    def previous_match(self) -> None:
        if not self._matches:
            return
        self._current_match = (self._current_match - 1) % len(self._matches)
        self._apply_search_highlights()
        self._goto_current_match()
        self._update_counter()

    def _update_counter(self) -> None:
        if not self._matches:
            self.counter_label.setText("0/0")
        else:
            self.counter_label.setText(f"{self._current_match + 1}/{len(self._matches)}")


class AuditReportWidget(QWidget):
    findingActivated = Signal(dict)

    HEADERS = [
        "Tipo",
        "Comportamento",
        "Arquivo",
        "Linha",
        "Incidente relacionado",
        "Explicação curta",
    ]

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._report: AuditReport | None = None
        self._package_dir: Path | None = None
        self._selected_finding: Finding | None = None
        self._all_findings: list[Finding] = []
        self._card_labels: dict[str, QLabel] = {}
        self._dashboard_cards: dict[str, QLabel] = {}
        self.classification_tables: dict[str, QTableWidget] = {}
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        self.path_label = QLabel("Pasta local: -")
        self.path_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.path_label.setObjectName("MutedLabel")
        layout.addWidget(self.path_label)

        self.status_frame = QFrame()
        self.status_frame.setObjectName("InstallStatusPanel")
        status_layout = QVBoxLayout(self.status_frame)
        status_layout.setContentsMargins(12, 10, 12, 10)
        status_layout.setSpacing(4)
        self.status_title = QLabel("NÃO VERIFICADO")
        self.status_title.setObjectName("InstallStatusTitle")
        self.status_subtitle = QLabel("Execute a auditoria antes de decidir.")
        self.status_subtitle.setObjectName("InstallStatusSubtitle")
        self.status_subtitle.setWordWrap(True)
        self.status_meta_label = QLabel("Evidências: -")
        self.status_meta_label.setObjectName("StatusMetaLabel")
        self.status_badges = QLabel("")
        self.status_badges.setObjectName("MutedLabel")
        self.status_badges.setWordWrap(True)
        status_layout.addWidget(self.status_title)
        status_layout.addWidget(self.status_subtitle)
        status_layout.addWidget(self.status_meta_label)
        status_layout.addWidget(self.status_badges)
        layout.addWidget(self.status_frame)

        self.safety_notice = QLabel(
            "O AUR Sentinel verifica se o pacote apresenta comportamento compatível com ataques reais ao AUR e supply chain. Se nada concreto for encontrado após a auditoria, o pacote fica verde: OK — PODE INSTALAR."
        )
        self.safety_notice.setObjectName("WarningLabel")
        self.safety_notice.setWordWrap(True)
        layout.addWidget(self.safety_notice)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)

        self.summary_widget = QWidget()
        self.summary_layout = QVBoxLayout(self.summary_widget)
        self.summary_layout.setContentsMargins(8, 8, 8, 8)
        self.summary_layout.setSpacing(8)
        self.cards_widget = QWidget()
        cards_layout = QGridLayout(self.cards_widget)
        cards_layout.setContentsMargins(0, 0, 0, 0)
        cards = [
            ("risk", "Status final"),
            ("findings", "Críticas"),
            ("commands", "Suspeitas concretas"),
            ("files", "Observações"),
            ("aur_modified", "Ultima alteracao AUR"),
            ("git_commit", "Etapas concluídas"),
        ]
        for index, (key, title) in enumerate(cards):
            card = self._summary_card(title)
            self._card_labels[key] = card.findChild(QLabel, "CardValue")  # type: ignore[assignment]
            cards_layout.addWidget(card, index // 3, index % 3)
        self.summary_layout.addWidget(self.cards_widget)

        self.category_table = QTableWidget(0, 2)
        self.category_table.setHorizontalHeaderLabels(["Categoria", "Total"])
        self.category_table.verticalHeader().setVisible(False)
        self.category_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.category_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.category_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.category_table.setMaximumHeight(180)
        self.summary_layout.addWidget(self.category_table)

        summary_actions = QHBoxLayout()
        self.copy_summary_button = QPushButton("Copiar relatorio resumido")
        self.copy_summary_button.clicked.connect(self.copy_summary_report)
        self.show_logs_button = QPushButton("Mostrar logs técnicos")
        self.show_logs_button.clicked.connect(self.show_logs)
        summary_actions.addStretch(1)
        summary_actions.addWidget(self.show_logs_button)
        summary_actions.addWidget(self.copy_summary_button)
        self.summary_layout.addLayout(summary_actions)

        self.summary_text = QPlainTextEdit()
        self.summary_text.setReadOnly(True)
        self.summary_text.setLineWrapMode(QPlainTextEdit.WidgetWidth)
        self.summary_layout.addWidget(self.summary_text, 1)
        self.tabs.addTab(self.summary_widget, "Resumo")

        self.analysis_widget = QWidget()
        analysis_layout = QVBoxLayout(self.analysis_widget)
        analysis_layout.setContentsMargins(8, 8, 8, 8)
        analysis_layout.setSpacing(8)
        self.analysis_status_title = QLabel("NÃO VERIFICADO")
        self.analysis_status_title.setObjectName("PanelTitle")
        analysis_layout.addWidget(self.analysis_status_title)
        self.analysis_table = QTableWidget(0, 2)
        self.analysis_table.setHorizontalHeaderLabels(["Item", "Status"])
        self.analysis_table.verticalHeader().setVisible(False)
        self.analysis_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.analysis_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.analysis_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        analysis_layout.addWidget(self.analysis_table, 1)
        self.tabs.addTab(self.analysis_widget, "O que foi analisado")

        self.findings_tab = QWidget()
        findings_layout = QVBoxLayout(self.findings_tab)
        findings_layout.setContentsMargins(0, 0, 0, 0)
        findings_layout.setSpacing(6)
        filter_row = QHBoxLayout()
        self.finding_search = QLineEdit()
        self.finding_search.setPlaceholderText("Pesquisar evidências")
        self.severity_filter = QComboBox()
        self.category_filter = QComboBox()
        self.file_filter = QComboBox()
        for combo, label in (
            (self.severity_filter, "Todas classificações"),
            (self.category_filter, "Todas categorias"),
            (self.file_filter, "Todos arquivos"),
        ):
            combo.addItem(label, "")
            combo.setMinimumWidth(150)
        filter_row.addWidget(self.finding_search, 1)
        filter_row.addWidget(self.severity_filter)
        filter_row.addWidget(self.category_filter)
        filter_row.addWidget(self.file_filter)
        findings_layout.addLayout(filter_row)

        self.findings_table = QTableWidget(0, len(self.HEADERS))
        self.findings_table.setHorizontalHeaderLabels(self.HEADERS)
        self.findings_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.findings_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.findings_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.findings_table.verticalHeader().setVisible(False)
        self.findings_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        for index, width in enumerate([95, 260, 170, 70, 220, 420]):
            self.findings_table.horizontalHeader().resizeSection(index, width)
        self.findings_table.itemSelectionChanged.connect(lambda: self._on_table_finding_selected(self.findings_table))
        findings_layout.addWidget(self.findings_table, 2)

        detail_frame = QFrame()
        detail_frame.setObjectName("FindingDetail")
        detail_layout = QVBoxLayout(detail_frame)
        detail_layout.setContentsMargins(8, 8, 8, 8)
        detail_header = QHBoxLayout()
        detail_title = QLabel("Detalhes da evidência")
        detail_title.setObjectName("PanelTitle")
        self.open_finding_button = QPushButton("Abrir no arquivo")
        self.copy_finding_button = QPushButton("Copiar evidência")
        self.filter_high_button = QPushButton("Filtrar críticos")
        self.open_finding_button.clicked.connect(self.open_selected_finding)
        self.copy_finding_button.clicked.connect(self.copy_selected_finding)
        self.filter_high_button.clicked.connect(self.filter_critical_high)
        detail_header.addWidget(detail_title)
        detail_header.addStretch(1)
        detail_header.addWidget(self.filter_high_button)
        detail_header.addWidget(self.copy_finding_button)
        detail_header.addWidget(self.open_finding_button)
        detail_layout.addLayout(detail_header)
        self.finding_details = QTextBrowser()
        self.finding_details.setOpenExternalLinks(False)
        self.finding_details.setMinimumHeight(145)
        detail_layout.addWidget(self.finding_details)
        findings_layout.addWidget(detail_frame, 1)
        self.tabs.addTab(self.findings_tab, "Evidências")
        for label, classification in (
            ("Suspeitas", "CONCRETE_SUSPICION"),
            ("Observações", "OBSERVATION"),
            ("Tudo", "ALL"),
        ):
            tab = QWidget()
            tab_layout = QVBoxLayout(tab)
            tab_layout.setContentsMargins(0, 0, 0, 0)
            table = QTableWidget(0, len(self.HEADERS))
            table.setHorizontalHeaderLabels(self.HEADERS)
            table.setSelectionBehavior(QAbstractItemView.SelectRows)
            table.setSelectionMode(QAbstractItemView.SingleSelection)
            table.setEditTriggers(QAbstractItemView.NoEditTriggers)
            table.verticalHeader().setVisible(False)
            table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
            for index, width in enumerate([95, 260, 170, 70, 220, 420]):
                table.horizontalHeader().resizeSection(index, width)
            table.itemSelectionChanged.connect(lambda table=table: self._on_table_finding_selected(table))
            tab_layout.addWidget(table, 1)
            self.classification_tables[classification] = table
            self.tabs.addTab(tab, label)

        self.finding_search.textChanged.connect(lambda _text: self._apply_finding_filters())
        self.severity_filter.currentIndexChanged.connect(lambda _index: self._apply_finding_filters())
        self.category_filter.currentIndexChanged.connect(lambda _index: self._apply_finding_filters())
        self.file_filter.currentIndexChanged.connect(lambda _index: self._apply_finding_filters())

        self.pkgbuild_editor = SearchableTextViewer("pkgbuild")
        self.srcinfo_editor = SearchableTextViewer("srcinfo")
        self.install_editor = SearchableTextViewer("install")
        self.git_editor = SearchableTextViewer("diff")
        self.logs_editor = SearchableTextViewer("log")
        self.file_editor = SearchableTextViewer("bash")
        self.json_report_editor = SearchableTextViewer("json")
        self.txt_report_editor = SearchableTextViewer("report")
        self.tabs.addTab(self.pkgbuild_editor, "PKGBUILD")
        self.tabs.addTab(self.srcinfo_editor, ".SRCINFO")
        self.tabs.addTab(self.install_editor, ".install")
        self.tabs.addTab(self.git_editor, "Git Diff")
        self.logs_tab = self._build_logs_tab()
        self.tabs.addTab(self.logs_tab, "Logs")
        self.source_matrix_table = QTableWidget(0, 10)
        self.source_matrix_table.setHorizontalHeaderLabels(
            ["Source", "Tipo", "Dominio", "Checksum", "Hash calculado", "Status", "PGP", "Upstream", "Risco", "Badges"]
        )
        self.source_matrix_table.verticalHeader().setVisible(False)
        self.source_matrix_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.source_matrix_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        for index, width in enumerate([220, 110, 150, 170, 210, 100, 120, 135, 100, 260]):
            self.source_matrix_table.horizontalHeader().resizeSection(index, width)
        self.tabs.addTab(self.source_matrix_table, "Matriz Sources")

        self.source_files_table = QTableWidget(0, 5)
        self.source_files_table.setHorizontalHeaderLabels(["Arquivo", "Tipo", "Tamanho", "Achados", "Tipo max."])
        self.source_files_table.verticalHeader().setVisible(False)
        self.source_files_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.source_files_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.source_files_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        for index in (1, 2, 3, 4):
            self.source_files_table.horizontalHeader().setSectionResizeMode(index, QHeaderView.ResizeToContents)
        self.source_files_table.itemDoubleClicked.connect(lambda _item: self.open_selected_source_file())
        self.tabs.addTab(self.source_files_table, "Arquivos Sources")

        self.tabs.addTab(self.json_report_editor, "JSON Report")
        self.tabs.addTab(self.txt_report_editor, "TXT Report")
        self.tabs.addTab(self.file_editor, "Arquivo")
        self.help_browser = QTextBrowser()
        self.help_browser.setOpenExternalLinks(True)
        self.help_browser.setHtml(self._help_html())
        self.tabs.addTab(self.help_browser, "Ajuda")

    def _build_logs_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        row = QHBoxLayout()
        self.clear_logs_button = QPushButton("Limpar logs")
        self.copy_logs_button = QPushButton("Copiar logs")
        self.save_logs_button = QPushButton("Salvar logs")
        self.clear_logs_button.clicked.connect(self.clear_logs)
        self.copy_logs_button.clicked.connect(self.copy_logs)
        self.save_logs_button.clicked.connect(self.save_logs)
        row.addStretch(1)
        row.addWidget(self.clear_logs_button)
        row.addWidget(self.copy_logs_button)
        row.addWidget(self.save_logs_button)
        layout.addLayout(row)
        layout.addWidget(self.logs_editor, 1)
        return widget

    def _summary_card(self, title: str) -> QFrame:
        card = QFrame()
        card.setObjectName("SummaryCard")
        card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(10, 8, 10, 8)
        label = QLabel(title)
        label.setObjectName("MutedLabel")
        value = QLabel("-")
        value.setObjectName("CardValue")
        value.setTextInteractionFlags(Qt.TextSelectableByMouse)
        value.setWordWrap(True)
        layout.addWidget(label)
        layout.addWidget(value)
        return card

    def show_package_metadata(self, package: dict[str, Any]) -> None:
        self._report = None
        self._selected_finding = None
        self._all_findings = []
        self._set_install_status(None)
        self.path_label.setText("Pasta local: -")
        self._update_summary_cards(None)
        self.category_table.setRowCount(0)
        self.summary_text.setPlainText(self._metadata_text(package))
        self._populate_dashboard(None)
        self._populate_source_matrix(None)
        self._populate_source_files(None)
        self.findings_table.setRowCount(0)
        for table in self.classification_tables.values():
            table.setRowCount(0)
        self.finding_details.setPlainText("")

    def set_package_path(self, path: Path) -> None:
        self._package_dir = path
        self.path_label.setText(f"Pasta local: {path}")

    def load_report(self, report: AuditReport) -> None:
        self._report = report
        self._package_dir = report.package_dir
        self._selected_finding = None
        self._all_findings = report.sorted_findings()
        counts = report.counts_by_severity
        self.path_label.setText(f"Pasta local: {report.package_dir}")
        self._set_install_status(report)
        self._update_summary_cards(report)
        self._populate_category_table(report)
        self.summary_text.setPlainText(self._report_summary_text(report))
        self._populate_dashboard(report)
        self._populate_source_matrix(report)
        self._populate_source_files(report)
        self._populate_filter_options(report)
        default_filter = "CONCRETE_FAILURE" if report.concrete_failures else "CONCRETE_SUSPICION"
        default_index = self.severity_filter.findData(default_filter)
        if default_index >= 0:
            self.severity_filter.setCurrentIndex(default_index)
        self._apply_finding_filters()
        self._populate_classification_tables(report)
        self._load_audit_files(report.package_dir)
        self.tabs.setCurrentWidget(
            self.findings_tab if (report.concrete_failures or report.concrete_suspicions) else self.summary_widget
        )

    def show_audit_running(self, stage: str) -> None:
        self.status_title.setText("AUDITORIA EM ANDAMENTO")
        self.status_subtitle.setText(stage)
        self.status_meta_label.setText("Pipeline completo em execução")
        self.status_badges.setText("Download, auditoria estática, sources, dependências e relatório")
        color = "#2563eb"
        self.status_frame.setStyleSheet(
            f"""
            #InstallStatusPanel {{
                border: 1px solid {color};
                border-left: 8px solid {color};
                border-radius: 6px;
                background: palette(base);
            }}
            #InstallStatusTitle {{
                color: {color};
                font-size: 18pt;
                font-weight: 800;
            }}
            #InstallStatusSubtitle {{
                font-size: 10.5pt;
                font-weight: 600;
            }}
            """
        )

    def _set_install_status(self, report: AuditReport | None) -> None:
        status = report.install_status if report else None
        text, subtitle, color = status_for_install_status(status)
        self.status_title.setText(text)
        self.status_subtitle.setText(subtitle)
        self.status_frame.setStyleSheet(
            f"""
            #InstallStatusPanel {{
                border: 1px solid {color};
                border-left: 8px solid {color};
                border-radius: 6px;
                background: palette(base);
            }}
            #InstallStatusTitle {{
                color: {color};
                font-size: 18pt;
                font-weight: 800;
            }}
            #InstallStatusSubtitle {{
                font-size: 10.5pt;
                font-weight: 600;
            }}
            """
        )
        if report:
            class_counts = report.counts_by_classification
            self.status_meta_label.setText(
                "Críticas: {failures} | Suspeitas: {suspicions} | "
                "Observações: {observations} | Etapas concluídas: {done}/{total}".format(
                    failures=class_counts.get("CONCRETE_FAILURE", 0),
                    suspicions=class_counts.get("CONCRETE_SUSPICION", 0),
                    observations=class_counts.get("OBSERVATION", 0),
                    done=self._completed_phase_count(report)[0],
                    total=self._completed_phase_count(report)[1],
                )
            )
            self.status_badges.setText(" · ".join(status.badges) if status else "")
        else:
            self.status_meta_label.setText("Evidências: -")
            self.status_badges.setText("")

    def append_log(self, text: str) -> None:
        cursor = self.logs_editor.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertText(text)
        self._trim_logs()
        self.logs_editor.setTextCursor(cursor)
        self.logs_editor.ensureCursorVisible()

    def _trim_logs(self) -> None:
        text = self.logs_editor.toPlainText()
        lines = text.splitlines()
        if len(lines) <= MAX_UI_LOG_LINES:
            return
        self.logs_editor.setPlainText("\n".join(lines[-MAX_UI_LOG_LINES:]) + "\n")

    def clear_logs(self) -> None:
        self.logs_editor.clear()

    def copy_logs(self) -> None:
        QApplication.clipboard().setText(self.logs_editor.toPlainText())

    def save_logs(self) -> None:
        default_path = str((self._package_dir or Path.home()) / "aur-sentinel-gui.log")
        path, _ = QFileDialog.getSaveFileName(self, "Salvar logs", default_path, "Log files (*.log *.txt);;All files (*)")
        if path:
            Path(path).write_text(self.logs_editor.toPlainText(), encoding="utf-8")

    def copy_selected_finding(self) -> None:
        if self._selected_finding:
            QApplication.clipboard().setText(
                json.dumps(self._selected_finding.to_dict(), indent=2, ensure_ascii=False)
            )

    def copy_summary_report(self) -> None:
        if self._report:
            QApplication.clipboard().setText(self._report_summary_text(self._report))

    def copy_ai_review_bundle(self) -> Path | None:
        if not self._report:
            return None
        bundle = create_ai_review_bundle(self._report)
        QApplication.clipboard().setText(bundle.clipboard_text)
        return bundle.file_path

    def show_json_report(self) -> None:
        self.tabs.setCurrentWidget(self.json_report_editor)

    def show_txt_report(self) -> None:
        self.tabs.setCurrentWidget(self.txt_report_editor)

    def show_help(self) -> None:
        self.tabs.setCurrentWidget(self.help_browser)

    def show_logs(self) -> None:
        self.tabs.setCurrentWidget(self.logs_tab)

    def filter_critical_high(self) -> None:
        index = self.severity_filter.findData("CONCRETE_FAILURE")
        if index < 0:
            self.severity_filter.addItem("FALHA CONCRETA", "CONCRETE_FAILURE")
            index = self.severity_filter.findData("CONCRETE_FAILURE")
        if index >= 0:
            self.severity_filter.setCurrentIndex(index)
        self.finding_search.setText("")

    def selected_finding(self) -> Finding | None:
        return self._selected_finding

    def open_selected_finding(self) -> None:
        if self._selected_finding:
            self.open_finding(self._selected_finding)

    def open_first_critical(self) -> None:
        if not self._report:
            return
        for finding in self._report.sorted_findings():
            if finding.status_impact == "RED":
                self.open_finding(finding)
                return

    def open_finding(self, finding: Finding) -> None:
        self._selected_finding = finding
        rel = finding.file_path
        if rel in {"AUR metadata", "."}:
            self.tabs.setCurrentWidget(self.summary_widget)
            return
        if rel == "Git diff":
            self.tabs.setCurrentWidget(self.git_editor)
            self.git_editor.goto_line(finding.line_start, finding.line_end)
            return
        if rel == "PKGBUILD":
            self.tabs.setCurrentWidget(self.pkgbuild_editor)
            self.pkgbuild_editor.goto_line(finding.line_start, finding.line_end)
            return
        if rel == ".SRCINFO":
            self.tabs.setCurrentWidget(self.srcinfo_editor)
            self.srcinfo_editor.goto_line(finding.line_start, finding.line_end)
            return
        if rel.endswith(".install") and self._package_dir:
            self._load_file_into_editor(rel, self.install_editor)
            self.tabs.setCurrentWidget(self.install_editor)
            self.install_editor.goto_line(finding.line_start, finding.line_end)
            return
        if self._package_dir:
            self._load_file_into_editor(rel, self.file_editor)
            self.tabs.setCurrentWidget(self.file_editor)
            self.file_editor.goto_line(finding.line_start, finding.line_end)

    def show_source_matrix(self) -> None:
        self.tabs.setCurrentWidget(self.source_matrix_table)

    def show_source_files(self) -> None:
        self.tabs.setCurrentWidget(self.source_files_table)

    def open_selected_source_file(self) -> None:
        selected = self.source_files_table.selectedItems()
        if not selected or not self._report or not self._report.source_tree:
            return
        row = selected[0].row()
        path_item = self.source_files_table.item(row, 0)
        if not path_item:
            return
        root = Path(self._report.source_tree.root)
        self._load_path_into_editor(root / path_item.text(), self.file_editor)
        self.tabs.setCurrentWidget(self.file_editor)

    def _populate_findings(self, rows: list[Finding]) -> None:
        self._fill_findings_table(self.findings_table, rows)

    def _populate_classification_tables(self, report: AuditReport) -> None:
        mapping = {
            "CONCRETE_SUSPICION": report.concrete_suspicions,
            "OBSERVATION": report.observations,
            "ALL": report.sorted_findings(),
        }
        for key, rows in mapping.items():
            table = self.classification_tables.get(key)
            if table:
                self._fill_findings_table(table, rows)

    def _fill_findings_table(self, table: QTableWidget, rows: list[Finding]) -> None:
        table.setRowCount(len(rows))
        for row, finding in enumerate(rows):
            line_text = ""
            if finding.line_start is not None:
                line_text = str(finding.line_start)
                if finding.line_end and finding.line_end != finding.line_start:
                    line_text += f"-{finding.line_end}"
            values = [
                CLASSIFICATION_LABELS.get(finding.classification, finding.classification),
                finding.behavior,
                finding.file_path,
                line_text,
                self._incident_label(finding),
                finding.why_it_matters or finding.risk_explanation,
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.UserRole, finding)
                if column == 0:
                    color = CLASSIFICATION_COLORS.get(finding.classification, QColor("#111827"))
                    item.setForeground(QColor("#ffffff") if finding.classification in {"CONCRETE_FAILURE"} else QColor("#111827"))
                    item.setBackground(color)
                    item.setTextAlignment(Qt.AlignCenter)
                table.setItem(row, column, item)

    def _incident_label(self, finding: Finding) -> str:
        if finding.incident_year or finding.related_incident_year or finding.incident_name or finding.related_incident_name:
            year = str(finding.incident_year or finding.related_incident_year or "")
            name = finding.incident_name or finding.related_incident_name or finding.name
            return f"{year} {name}".strip()
        return "-"

    def _populate_filter_options(self, report: AuditReport) -> None:
        current_values = (
            self.severity_filter.currentData(),
            self.category_filter.currentData(),
            self.file_filter.currentData(),
        )
        self._reset_combo(
            self.severity_filter,
            "Todas classificações",
            [
                value
                for value in ("CONCRETE_FAILURE", "CONCRETE_SUSPICION", "OBSERVATION", "INFO")
                if report.counts_by_classification.get(value, 0)
            ],
            labels=CLASSIFICATION_LABELS,
        )
        self._reset_combo(self.category_filter, "Todas categorias", sorted(report.counts_by_category))
        self._reset_combo(self.file_filter, "Todos arquivos", sorted(report.counts_by_file))
        for combo, value in zip(
            (self.severity_filter, self.category_filter, self.file_filter),
            current_values,
        ):
            index = combo.findData(value)
            if index >= 0:
                combo.setCurrentIndex(index)

    def _reset_combo(
        self,
        combo: QComboBox,
        label: str,
        values: list[str],
        labels: dict[str, str] | None = None,
    ) -> None:
        combo.blockSignals(True)
        combo.clear()
        combo.addItem(label, "")
        for value in values:
            combo.addItem((labels or {}).get(value, value), value)
        combo.blockSignals(False)

    def _apply_finding_filters(self) -> None:
        text = self.finding_search.text().strip().lower()
        severity = self.severity_filter.currentData()
        category = self.category_filter.currentData()
        file_path = self.file_filter.currentData()
        rows: list[Finding] = []
        for finding in self._all_findings:
            haystack = " ".join(
                [
                    finding.classification,
                    finding.severity,
                    finding.category,
                    finding.file_path,
                    finding.name,
                    finding.incident_name or "",
                    finding.incident_similarity or "",
                    finding.command or "",
                    finding.matched_text,
                    finding.description,
                    finding.risk_explanation,
                    finding.recommendation,
                ]
            ).lower()
            if severity and finding.classification != severity:
                continue
            if category and finding.category != category:
                continue
            if file_path and finding.file_path != file_path:
                continue
            if text and text not in haystack:
                continue
            rows.append(finding)
        self._populate_findings(rows)
        if not self._all_findings:
            self.finding_details.setPlainText("Nenhuma evidência relevante encontrada.")
        elif not rows:
            self.finding_details.setPlainText("Nenhuma evidência encontrada com os filtros atuais.")

    def _on_finding_selected(self) -> None:
        self._on_table_finding_selected(self.findings_table)

    def _on_table_finding_selected(self, table: QTableWidget) -> None:
        selected = table.selectedItems()
        if not selected:
            return
        row = selected[0].row()
        item = table.item(row, 0)
        finding = item.data(Qt.UserRole) if item else None
        if isinstance(finding, Finding):
            self._selected_finding = finding
            self.findingActivated.emit(finding.to_dict())
            self._show_finding_details(finding)
            self.open_finding(finding)

    def _show_finding_details(self, finding: Finding) -> None:
        location = finding.file_path
        if finding.line_start is not None:
            location += f":{finding.line_start}"
            if finding.line_end and finding.line_end != finding.line_start:
                location += f"-{finding.line_end}"
        detail_html = f"""
        <h3>{html.escape(CLASSIFICATION_LABELS.get(finding.classification, finding.classification))} - {html.escape(finding.name)}</h3>
        <p><b>Incidente relacionado:</b> {html.escape(self._incident_label(finding))}</p>
        <p><b>Arquivo:</b> {html.escape(location)}</p>
        <p><b>Comportamento:</b> {html.escape(finding.behavior)}</p>
        <p><b>Trecho:</b><br><code>{html.escape(finding.matched_text)}</code></p>
        <p><b>Por que importa:</b> {html.escape(finding.why_it_matters)}</p>
        <p><b>Recomendacao:</b> {html.escape(finding.recommendation)}</p>
        """
        self.finding_details.setHtml(detail_html)

    def _update_summary_cards(self, report: AuditReport | None) -> None:
        values = {
            "risk": "-",
            "findings": "-",
            "commands": "-",
            "files": "-",
            "aur_modified": "-",
            "git_commit": "-",
        }
        if report:
            class_counts = report.counts_by_classification
            completed, total = self._completed_phase_count(report)
            values.update(
                {
                    "risk": report.install_status.text,
                    "findings": str(class_counts.get("CONCRETE_FAILURE", 0)),
                    "commands": str(class_counts.get("CONCRETE_SUSPICION", 0)),
                    "files": str(class_counts.get("OBSERVATION", 0)),
                    "aur_modified": format_unix_timestamp(report.metadata.get("LastModified")) or "-",
                    "git_commit": f"{completed}/{total}",
                }
            )
        for key, value in values.items():
            label = self._card_labels.get(key)
            if label:
                label.setText(value)

    def _completed_phase_count(self, report: AuditReport) -> tuple[int, int]:
        phases = report.to_dict().get("audit_completion", {})
        relevant = {
            key: value
            for key, value in phases.items()
            if key
            in {
                "aur_repo",
                "pkgbuild",
                "srcinfo",
                "install_scripts",
                "git_history",
                "source_verification",
                "source_extraction",
                "archive_analysis",
                "deep_file_scan",
            }
        }
        total = len(relevant)
        completed = sum(1 for value in relevant.values() if value in {"completed", "not_applicable"})
        return completed, total

    def _populate_dashboard(self, report: AuditReport | None) -> None:
        if not report:
            self.analysis_status_title.setText("NÃO VERIFICADO")
            self.analysis_table.setRowCount(0)
            return

        self.analysis_status_title.setText(report.install_status.text)
        labels = {
            "pkgbuild": "PKGBUILD",
            "srcinfo": ".SRCINFO",
            "install_scripts": "*.install",
            "git_history": "Histórico Git",
            "sources": "Sources",
            "archives": "Arquivos compactados",
            "scripts": "Scripts",
            "binaries": "Binários",
            "checksums": "Checksums",
            "pgp": "PGP",
        }
        rows = list(report.analysis_status().items())
        self.analysis_table.setRowCount(len(rows))
        for row, (key, value) in enumerate(rows):
            self.analysis_table.setItem(row, 0, QTableWidgetItem(labels.get(key, key)))
            item = QTableWidgetItem(value)
            normalized = value.lower()
            if normalized in {"falhou", "erro"}:
                item.setBackground(QColor("#dc2626"))
                item.setForeground(QColor("#ffffff"))
            elif normalized in {"parcial", "não analisado"}:
                item.setBackground(QColor("#f59e0b"))
                item.setForeground(QColor("#111827"))
            elif normalized in {"não existe", "não disponível", "não aplicável", "não encontrados"}:
                item.setBackground(QColor("#e5e7eb"))
                item.setForeground(QColor("#111827"))
            else:
                item.setBackground(QColor("#16a34a"))
                item.setForeground(QColor("#ffffff"))
            self.analysis_table.setItem(row, 1, item)

    def _source_integrity_status(self, summary: dict[str, Any]) -> str:
        if not summary:
            return "Nao verificado"
        if summary.get("invalid_checksums", 0):
            return f"Critico: {summary['invalid_checksums']} checksum invalido"
        if summary.get("skipped_checksums", 0) or summary.get("missing_checksums", 0):
            return f"Atencao: {summary.get('skipped_checksums', 0)} SKIP / {summary.get('missing_checksums', 0)} ausentes"
        if summary.get("valid_checksums", 0):
            return f"OK local: {summary['valid_checksums']} checksum(s)"
        return "Sem checksum local confirmado"

    def _file_status(self, report: AuditReport, file_path: str) -> str:
        hits = [item for item in report.findings if item.file_path == file_path]
        if not hits:
            return "OK observado"
        red = sum(1 for item in hits if item.status_impact == "RED")
        orange = sum(1 for item in hits if item.status_impact == "ORANGE")
        yellow = sum(1 for item in hits if item.status_impact == "YELLOW")
        if red:
            return f"Crítico: {red}"
        if orange:
            return f"Alto: {orange}"
        if yellow:
            return f"Revisar: {yellow}"
        return f"Revisar: {len(hits)}"

    def _source_tree_status(self, summary: dict[str, Any]) -> str:
        if not summary:
            return "Nao verificado"
        files = summary.get("files_scanned", 0)
        scripts = summary.get("scripts_found", 0)
        return f"{files} arquivo(s), {scripts} script(s)"

    def _pgp_status(self, summary: dict[str, Any]) -> str:
        if not summary:
            return "Nao verificado"
        if summary.get("pgp_invalid", 0):
            return f"Critico: {summary['pgp_invalid']} invalido"
        if summary.get("pgp_valid", 0):
            return f"OK: {summary['pgp_valid']} valido"
        return f"Nao verificado: {summary.get('pgp_not_verified', 0)}"

    def _category_status(self, report: AuditReport, categories: set[str]) -> str:
        hits = [item for item in report.findings if item.category in categories or item.source in categories]
        red = sum(1 for item in hits if item.status_impact == "RED")
        orange = sum(1 for item in hits if item.status_impact == "ORANGE")
        if red:
            return f"Critico: {red}"
        if orange:
            return f"Risco: {orange}"
        if hits:
            return f"Observado: {len(hits)}"
        return "OK observado"

    def _install_script_status(self, report: AuditReport) -> str:
        hits = [item for item in report.findings if item.file_path.endswith(".install") or item.category == "install_scriptlet"]
        if not hits:
            return "Nenhum .install"
        red = sum(1 for item in hits if item.status_impact == "RED")
        orange = sum(1 for item in hits if item.status_impact == "ORANGE")
        yellow = sum(1 for item in hits if item.status_impact == "YELLOW")
        if red:
            return f"Critico: {red}"
        if orange:
            return f"Risco: {orange}"
        if yellow:
            return f"Revisar: {yellow}"
        return f"Revisar: {len(hits)}"

    def _dependency_manager_status(self, report: AuditReport, tree_summary: dict[str, Any]) -> str:
        tools = tree_summary.get("package_managers_detected") or []
        hits = [item for item in report.findings if item.category == "dependency_manager" and item.status_impact != "NONE"]
        if hits or tools:
            return f"{len(hits)} evidência(s); {', '.join(tools) or 'repo AUR'}"
        return "Nenhum relevante"

    def _history_status(self, report: AuditReport) -> str:
        recent = report.trust.recent_update_analysis if report.trust else None
        if recent and recent.recent_update_detected and not recent.penalized:
            return "Update recente neutro"
        if recent and recent.penalized:
            return "Update recente penalizado"
        return self._category_status(report, {"recent_sensitive_change", "git"})

    def _known_incident_status(self, report: AuditReport) -> str:
        hits = [
            item
            for item in report.findings
            if item.category in {"known_incident_pattern", "known_campaign_indicator"}
            and item.status_impact != "NONE"
        ]
        if not hits:
            return "Nenhum encontrado"
        critical = sum(1 for item in hits if item.status_impact == "RED")
        if critical:
            return f"Crítico: {critical}"
        return f"Revisar: {len(hits)}"

    def _binary_status(self, tree_summary: dict[str, Any]) -> str:
        if not tree_summary:
            return "Nao verificado"
        count = tree_summary.get("binaries_found", 0)
        return f"{count} binario(s)" if count else "Nenhum binario"

    def _populate_source_matrix(self, report: AuditReport | None) -> None:
        sources = list(report.source_integrity.sources) if report and report.source_integrity else []
        self.source_matrix_table.setRowCount(len(sources))
        for row, source in enumerate(sources):
            hash_text = source.calculated_hashes.get("sha256") or source.calculated_hashes.get("sha512") or ""
            values = [
                source.name,
                source.kind,
                source.domain,
                f"{source.checksum_algorithm or '-'} {source.declared_checksum or ''}".strip(),
                hash_text,
                source.checksum_status,
                source.pgp_status,
                source.upstream_status,
                status_for_source_risk(source.risk)[0],
                ", ".join(source.badges),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if column == 8:
                    _status, color = status_for_source_risk(source.risk)
                    item.setBackground(QColor(color))
                    item.setForeground(QColor("#ffffff"))
                self.source_matrix_table.setItem(row, column, item)

    def _populate_source_files(self, report: AuditReport | None) -> None:
        files = list(report.source_tree.scanned_files) if report and report.source_tree else []
        self.source_files_table.setRowCount(len(files))
        for row, scanned in enumerate(files):
            values = [
                scanned.path,
                scanned.kind,
                str(scanned.size),
                str(scanned.findings),
                self._severity_display(scanned.max_severity),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 4:
                    color = SEVERITY_COLORS.get(scanned.max_severity, QColor("#6b7280"))
                    item.setBackground(color)
                    item.setForeground(QColor("#ffffff") if scanned.max_severity in {"HIGH", "CRITICAL"} else QColor("#111827"))
                self.source_files_table.setItem(row, column, item)

    def _severity_display(self, severity: str) -> str:
        if severity == "CRITICAL":
            return "Crítico"
        if severity in {"HIGH", "MEDIUM", "REVIEW"}:
            return "Suspeito"
        if severity in {"LOW", "OBSERVATION"}:
            return "Observação"
        return "Info"

    def _populate_category_table(self, report: AuditReport) -> None:
        rows = list(report.counts_by_category.items())
        self.category_table.setRowCount(len(rows))
        for row, (category, count) in enumerate(rows):
            self.category_table.setItem(row, 0, QTableWidgetItem(category))
            count_item = QTableWidgetItem(str(count))
            count_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.category_table.setItem(row, 1, count_item)

    def _load_audit_files(self, package_dir: Path) -> None:
        self._load_file_into_editor("PKGBUILD", self.pkgbuild_editor)
        self._load_file_into_editor(".SRCINFO", self.srcinfo_editor)
        self._load_file_into_editor("audit-report.json", self.json_report_editor)
        self._load_file_into_editor("audit-report.txt", self.txt_report_editor)
        install_files = sorted(path.relative_to(package_dir).as_posix() for path in package_dir.rglob("*.install"))
        if not install_files:
            self.install_editor.setPlainText("Nenhum arquivo .install encontrado.")
        elif len(install_files) == 1:
            self._load_file_into_editor(install_files[0], self.install_editor)
        else:
            combined = []
            for rel in install_files:
                path = package_dir / rel
                combined.append(f"===== {rel} =====\n")
                text, truncated = safe_read_text(path, max_bytes=MAX_FILE_PREVIEW_BYTES)
                combined.append(text)
                if truncated:
                    combined.append("\n[Arquivo grande. Exibindo prévia.]\n")
                combined.append("\n")
            self.install_editor.setPlainText("".join(combined))
        if self._report:
            git_parts = [
                "git log --oneline --decorate -n 20",
                self._report.git.log_oneline or "(sem saida)",
                "",
                "git show --stat --oneline HEAD",
                self._report.git.show_stat or "(sem saida)",
                "",
                "git diff HEAD~1..HEAD -- PKGBUILD .SRCINFO '*.install'",
                self._report.git.recent_diff or "(sem diff)",
            ]
            self.git_editor.setPlainText("\n".join(git_parts))

    def _load_file_into_editor(self, rel: str, editor: SearchableTextViewer) -> None:
        if not self._package_dir:
            editor.setPlainText("Pasta do pacote nao definida.")
            return
        path = self._resolve_display_file(rel)
        if not path.exists():
            editor.setPlainText(f"Arquivo nao encontrado: {rel}")
            return
        self._load_path_into_editor(path, editor)

    def _resolve_display_file(self, rel: str) -> Path:
        assert self._package_dir is not None
        candidates = [self._package_dir / rel]
        if rel in {"audit-report.json", "audit-report.txt"}:
            candidates.append(self._package_dir.parent / "reports" / rel)
        if self._report and self._report.source_tree:
            candidates.append(Path(self._report.source_tree.root) / rel)
        for candidate in candidates:
            if candidate.exists():
                return candidate
        return candidates[0]

    def _load_path_into_editor(self, path: Path, editor: SearchableTextViewer) -> None:
        try:
            size = path.stat().st_size
        except OSError as exc:
            editor.setPlainText(f"Arquivo não pôde ser lido: {exc}")
            return
        if is_probably_binary(path):
            editor.set_highlighter("report")
            editor.setPlainText(
                "Arquivo binário. A GUI não abre binários como texto.\n\n"
                f"Caminho: {path}\n"
                f"Tamanho: {size} bytes\n"
            )
            return
        if path.name == ".SRCINFO":
            editor.set_highlighter("srcinfo")
        elif path.name == "audit-report.json" or path.suffix == ".json":
            editor.set_highlighter("json")
        elif path.name == "audit-report.txt" or path.suffix == ".txt":
            editor.set_highlighter("report")
        elif path.suffix in {".install", ".sh"} or path.name == "PKGBUILD":
            editor.set_highlighter("bash")
        elif path.suffix == ".diff":
            editor.set_highlighter("diff")
        if size > MAX_FILE_PREVIEW_BYTES:
            text, _ = safe_read_text(path, max_bytes=MAX_FILE_PREVIEW_BYTES)
            editor.setPlainText(
                "Arquivo grande. Exibindo prévia. Use abrir externamente para ver completo.\n\n"
                + text
            )
            return
        editor.setPlainText(path.read_text(encoding="utf-8", errors="replace"))

    def _help_html(self) -> str:
        return """
        <h1>Para que serve o AUR Sentinel?</h1>
        <p>O AUR Sentinel analisa pacotes do Arch User Repository antes da instalação.</p>
        <p>Ele procura comportamentos associados a falhas documentadas do AUR e ataques de supply chain, como:</p>
        <ul>
          <li>execução remota direta, por exemplo <code>curl | bash</code>;</li>
          <li>scripts <code>.install</code> perigosos;</li>
          <li>persistência via systemd, cron ou shell profiles;</li>
          <li>exfiltração de chaves, tokens, cookies ou credenciais;</li>
          <li>uso suspeito de npm, Bun, pnpm, pip, Go, Cargo ou outros gerenciadores durante instalação;</li>
          <li>indicadores conhecidos de incidentes AUR, como atomic-lockfile, js-digest e lockfile-js;</li>
          <li>alterações perigosas similares aos incidentes públicos de 2018, 2025 e 2026.</li>
        </ul>
        <p>Ele também verifica PKGBUILD, .SRCINFO, arquivos *.install, histórico Git recente, sources baixados pelo makepkg, checksums e assinaturas quando disponíveis, arquivos compactados extraídos, scripts de instalação, arquivos .sh, .service, .desktop, package.json, setup.py, build.rs, go.mod, gradle e outros, binários inesperados e strings suspeitas.</p>
        <p>Resultado esperado:</p>
        <ul>
          <li>Verde: nenhum comportamento nocivo ou padrão documentado foi encontrado.</li>
          <li>Suspeito: há evidência concreta que precisa de análise manual.</li>
          <li>Vermelho: há comportamento compatível com falhas reais do AUR/supply chain ou ação nociva concreta.</li>
        </ul>
        <p>O AUR Sentinel não garante segurança absoluta. Ele reduz risco analisando evidências técnicas antes da instalação.</p>

        <h1>Como interpretar o resultado</h1>
        <p><b>Verde — OK — PODE INSTALAR:</b><br>A auditoria não encontrou comportamento nocivo nem padrão conhecido de falhas do AUR. Ainda não é garantia absoluta de segurança.</p>
        <p><b>Amarelo/Laranja — SUSPEITO — ANALISAR:</b><br>Existe uma evidência concreta que precisa de revisão manual. Não é necessariamente malware.</p>
        <p><b>Vermelho — CRÍTICO — NÃO RECOMENDADO:</b><br>Foi encontrado comportamento compatível com falhas reais do AUR/supply chain ou ação nociva concreta.</p>
        <p><b>Observações:</b><br>São informações úteis, mas não indicam risco por si só. Exemplos: pacote popular, GitHub upstream, pacote -bin, Electron, .desktop, update recente normal.</p>

        <h1>Incidentes AUR considerados</h1>
        <ul>
          <li>AUR 2018 acroread/balz/minergate</li>
          <li>AUR 2025 fake browser patch packages / CHAOS RAT</li>
          <li>AUR 2026 Atomic Arch npm/Bun dependency campaign</li>
          <li>AUR 2026 shell profile modification/spam</li>
        </ul>
        """

    def _metadata_text(self, package: dict[str, Any]) -> str:
        lines = [
            "Metadados AUR",
            f"Nome: {package.get('Name', '')}",
            f"Versao: {package.get('Version', '')}",
            f"Descricao: {package.get('Description', '')}",
            f"Mantenedor: {package.get('Maintainer') or '(sem mantenedor)'}",
            f"Votos: {package.get('NumVotes', 0)}",
            f"Popularidade: {package.get('Popularity', 0)}",
            f"Criado: {format_unix_timestamp(package.get('FirstSubmitted'))}",
            f"Ultima modificacao: {format_unix_timestamp(package.get('LastModified'))}",
            f"Out-of-date: {format_unix_timestamp(package.get('OutOfDate')) if package.get('OutOfDate') else '-'}",
            f"URL: {package.get('URL', '')}",
            f"Licenca: {', '.join(package.get('License') or [])}",
            f"Depends: {', '.join(package.get('Depends') or [])}",
            f"MakeDepends: {', '.join(package.get('MakeDepends') or [])}",
            "",
            "Aviso: AUR e conteudo mantido pela comunidade. Nenhuma ferramenta estatica garante ausencia de malware.",
        ]
        return "\n".join(lines)

    def _report_summary_text(self, report: AuditReport) -> str:
        metadata = self._metadata_text(report.metadata)
        git = report.git
        category_lines = [
            f"{category}: {count}"
            for category, count in report.counts_by_category.items()
        ] or ["-"]
        file_lines = [
            f"{file_path}: {count}"
            for file_path, count in report.counts_by_file.items()
        ] or ["-"]
        lines = [
            metadata,
            "",
            "Resumo da auditoria",
            f"Status: {report.install_status.text}",
            f"Subtitulo: {report.install_status.subtitle}",
            "",
            "Resultado em linguagem simples",
            self._simple_result_text(report),
            "",
            f"Falhas críticas: {len(report.concrete_failures)}",
            f"Suspeitas concretas: {len(report.concrete_suspicions)}",
            f"Observações: {len(report.observations)}",
            f"Informativos: {len(report.info)}",
            "",
            "Motivo do status",
            *[f"- {reason}" for reason in report.install_status.reasons],
            "",
            "Recomendacao",
            *[f"- {item}" for item in report.install_status.recommendations],
            "",
            "Contagem por classificação",
            *[
                f"{CLASSIFICATION_LABELS.get(key, key)}: {value}"
                for key, value in report.counts_by_classification.items()
            ],
            "",
            "Contagem por categoria",
            *category_lines,
            "",
            "Contagem por arquivo",
            *file_lines,
            "",
            f"Relatorio JSON: {report.package_dir / 'audit-report.json'}",
            f"Relatorio TXT: {report.package_dir / 'audit-report.txt'}",
            f"Hashes: {report.package_dir / 'file-hashes.sha256'}",
            f"Relatorios v2: {report.package_dir.parent / 'reports'}",
            f"Hashes v2: {report.package_dir.parent / 'hashes'}",
            "",
            "Git",
            f"Ultimo commit: {git.last_commit}",
            f"Data: {git.last_commit_date}",
            f"Autor: {git.last_commit_author}",
            "Arquivos alterados:",
            *(git.changed_files or ["-"]),
            "",
            "Interpretacao",
            (
                "Observações são neutras e não mudam o resultado. "
                "O resultado verde indica que nenhum comportamento nocivo ou padrão documentado foi encontrado."
            ),
        ]
        return "\n".join(lines)

    def _simple_result_text(self, report: AuditReport) -> str:
        verdict = report.final_verdict.verdict
        if verdict == "OK_INSTALL":
            return (
                "Nenhum comportamento nocivo foi encontrado.\n\n"
                "A auditoria analisou PKGBUILD, .SRCINFO, scripts de instalação, histórico Git, sources, "
                "arquivos extraídos e padrões conhecidos de incidentes AUR.\n\n"
                "Não foram encontrados padrões como curl | bash, npm install malicioso em .install, "
                "persistência, exfiltração, obfuscação executável ou alteração de shell profile.\n\n"
                "Resultado: OK — PODE INSTALAR."
            )
        if verdict == "SUSPICIOUS_ANALYZE":
            return (
                "Foi encontrada evidência que exige revisão.\n\n"
                "O pacote não corresponde diretamente a um incidente conhecido, mas executa uma ação sensível "
                "que pode ser legítima ou nociva dependendo do contexto.\n\n"
                "Revise os itens abaixo antes de instalar."
            )
        if verdict == "CRITICAL_NOT_RECOMMENDED":
            return (
                "Foi encontrado comportamento crítico.\n\n"
                "O pacote contém padrão compatível com falhas reais do AUR/supply chain ou ação nociva concreta.\n\n"
                "Recomenda-se não instalar sem análise manual detalhada."
            )
        return "Execute a auditoria antes de decidir."
