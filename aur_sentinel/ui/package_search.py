from __future__ import annotations

import html
from typing import Any
from urllib.parse import quote

from PySide6.QtCore import QObject, Qt, QThread, QTimer, Signal, Slot
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from aur_sentinel.aur.search_service import AurSearchService
from aur_sentinel.utils.timefmt import format_unix_timestamp


class SearchWorker(QObject):
    resultsReady = Signal(list)
    error = Signal(str)
    finished = Signal()

    def __init__(self, query: str) -> None:
        super().__init__()
        self.query = query

    @Slot()
    def run(self) -> None:
        try:
            self.resultsReady.emit(AurSearchService().searchPackages(self.query))
        except Exception as exc:  # GUI boundary: show clear error
            self.error.emit(str(exc))
        finally:
            self.finished.emit()


class InfoWorker(QObject):
    infoReady = Signal(str, dict)
    error = Signal(str, str)
    finished = Signal()

    def __init__(self, package_name: str) -> None:
        super().__init__()
        self.package_name = package_name

    @Slot()
    def run(self) -> None:
        try:
            info = AurSearchService().fetchPackageInfo(self.package_name)
            self.infoReady.emit(self.package_name, info)
        except Exception as exc:  # GUI boundary: keep the selected search row usable
            self.error.emit(self.package_name, str(exc))
        finally:
            self.finished.emit()


class PackageSearchWidget(QWidget):
    packageSelected = Signal(dict)
    statusChanged = Signal(str)

    INITIAL_WIDTHS = [180, 130, 420, 150, 70, 105]

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._thread: QThread | None = None
        self._worker: SearchWorker | None = None
        self._info_thread: QThread | None = None
        self._info_worker: InfoWorker | None = None
        self._pending_info_name: str | None = None
        self._selected_package: dict[str, Any] | None = None
        self._column_widths_initialized = False
        self._debounce_timer = QTimer(self)
        self._debounce_timer.setSingleShot(True)
        self._debounce_timer.setInterval(650)
        self._debounce_timer.timeout.connect(self.search)
        self._build_ui()
        self._render_info(None)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        title_row = QHBoxLayout()
        self.title_label = QLabel()
        self.title_label.setObjectName("PanelTitle")
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        self.status_label.setObjectName("MutedLabel")
        title_row.addWidget(self.title_label)
        title_row.addWidget(self.status_label, 1, Qt.AlignRight)
        layout.addLayout(title_row)

        search_row = QHBoxLayout()
        search_row.setSpacing(8)
        self.search_edit = QLineEdit()
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.returnPressed.connect(self.search)
        self.search_edit.textChanged.connect(self._schedule_search)
        self.search_button = QPushButton()
        self.search_button.clicked.connect(self.search)
        search_row.addWidget(self.search_edit, 1)
        search_row.addWidget(self.search_button)
        layout.addLayout(search_row)

        content_row = QHBoxLayout()
        content_row.setSpacing(10)

        self.table = QTableWidget(0, len(self._headers()))
        self.table.setObjectName("SearchResults")
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setMinimumHeight(170)
        header = self.table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionsMovable(False)
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.sectionResized.connect(self._manual_column_resize)
        self._apply_initial_column_widths()
        self.table.itemSelectionChanged.connect(self._on_selection_changed)
        content_row.addWidget(self.table, 3)

        self.info_card = QFrame()
        self.info_card.setObjectName("PackageInfoCard")
        self.info_card.setMinimumWidth(320)
        info_layout = QVBoxLayout(self.info_card)
        info_layout.setContentsMargins(12, 10, 12, 10)
        info_layout.setSpacing(6)
        self.info_title = QLabel()
        self.info_title.setObjectName("PanelTitle")
        self.info_browser = QTextBrowser()
        self.info_browser.setObjectName("PackageInfo")
        self.info_browser.setOpenExternalLinks(True)
        self.info_browser.setMinimumHeight(150)
        info_layout.addWidget(self.info_title)
        info_layout.addWidget(self.info_browser, 1)
        content_row.addWidget(self.info_card, 2)

        layout.addLayout(content_row, 1)

        self.notice_label = QLabel()
        self.notice_label.setWordWrap(True)
        self.notice_label.setObjectName("MutedLabel")
        layout.addWidget(self.notice_label)
        self.retranslateUi()

    def retranslateUi(self) -> None:
        self.title_label.setText(self.tr("Buscar pacote AUR"))
        self.search_edit.setPlaceholderText(self.tr("Nome do pacote AUR"))
        self.search_button.setText(self.tr("Buscar"))
        self.table.setHorizontalHeaderLabels(self._headers())
        self.info_title.setText(self.tr("Informações do pacote"))
        self.notice_label.setText(
            self.tr("AUR é mantido pela comunidade. O Aur Sentinel audita antes de compilar e não usa helper AUR.")
        )
        self._refresh_status_text()
        self._render_info(self._selected_package)

    def _headers(self) -> list[str]:
        return [
            self.tr("Nome"),
            self.tr("Versão"),
            self.tr("Descrição"),
            self.tr("Mantenedor"),
            self.tr("Votos"),
            self.tr("Popularidade"),
        ]

    def _refresh_status_text(self) -> None:
        name = str((self._selected_package or {}).get("Name", "")).strip()
        if name:
            self.status_label.setText(self.tr("Pacote selecionado: {package}").format(package=name))
        elif len(self.search_edit.text().strip()) < 2:
            self.status_label.setText(self.tr("Digite pelo menos 2 caracteres para consultar a AUR."))

    def selected_package(self) -> dict[str, Any] | None:
        return self._selected_package

    def clear_search(self) -> None:
        self.search_edit.clear()
        self.table.setRowCount(0)
        self._selected_package = None
        self._render_info(None)
        self._set_status(self.tr("Digite pelo menos 2 caracteres para consultar a AUR."))

    def refresh_results(self) -> None:
        if self.search_edit.text().strip():
            self.search()
        else:
            self._set_status(self.tr("Informe um termo de busca."))

    def _apply_initial_column_widths(self) -> None:
        if self._column_widths_initialized:
            return
        for index, width in enumerate(self.INITIAL_WIDTHS):
            self.table.horizontalHeader().resizeSection(index, width)
        self._column_widths_initialized = True

    def _manual_column_resize(self, _logical_index: int, _old_size: int, _new_size: int) -> None:
        self._column_widths_initialized = True

    @Slot(str)
    def _schedule_search(self, text: str) -> None:
        query = text.strip()
        if len(query) < 2:
            self._debounce_timer.stop()
            self.table.setRowCount(0)
            self._selected_package = None
            self._render_info(None)
            self._set_status(self.tr("Digite pelo menos 2 caracteres para consultar a AUR."))
            self.packageSelected.emit({})
            return
        self._debounce_timer.start()

    @Slot()
    def search(self) -> None:
        self._debounce_timer.stop()
        query = self.search_edit.text().strip()
        if len(query) < 2:
            self._set_status(self.tr("Digite pelo menos 2 caracteres para consultar a AUR."))
            return
        if self._thread and self._thread.isRunning():
            self._set_status(self.tr("Busca em andamento; aguarde."))
            return
        self.search_button.setEnabled(False)
        self._set_status(self.tr("Buscando '{query}' na AUR...").format(query=query))
        self.table.setRowCount(0)
        self._selected_package = None
        self._render_info(None)
        self.packageSelected.emit({})

        self._thread = QThread(self)
        self._worker = SearchWorker(query)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.resultsReady.connect(self._populate_results)
        self._worker.error.connect(self._show_error)
        self._worker.finished.connect(self._thread.quit)
        self._worker.finished.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._thread.deleteLater)
        self._thread.finished.connect(self._search_finished)
        self._thread.start()

    @Slot(list)
    def _populate_results(self, rows: list[dict[str, Any]]) -> None:
        self.table.setRowCount(len(rows))
        self._apply_initial_column_widths()
        for row_index, package in enumerate(rows):
            values = [
                package.get("Name", ""),
                package.get("Version", ""),
                package.get("Description", ""),
                package.get("Maintainer") or self.tr("(sem mantenedor)"),
                str(package.get("NumVotes", 0)),
                f"{float(package.get('Popularity') or 0):.6f}",
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if column in (4, 5):
                    item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                if column == 0:
                    item.setData(Qt.UserRole, package)
                self.table.setItem(row_index, column, item)
        self._set_status(
            self.tr("{count} resultado(s) encontrados. Selecione um pacote para auditar.").format(count=len(rows))
        )

    @Slot(str)
    def _show_error(self, message: str) -> None:
        self._set_status(message)

    @Slot()
    def _search_finished(self) -> None:
        self.search_button.setEnabled(True)
        self._thread = None
        self._worker = None

    def _on_selection_changed(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        row = rows[0].row()
        item = self.table.item(row, 0)
        package = item.data(Qt.UserRole) if item else None
        if not isinstance(package, dict):
            return
        self._selected_package = dict(package)
        name = str(package.get("Name", ""))
        self.search_edit.blockSignals(True)
        self.search_edit.setText(name)
        self.search_edit.blockSignals(False)
        self._render_info(self._selected_package)
        self._set_status(self.tr("Pacote selecionado: {package}").format(package=name))
        self.packageSelected.emit(self._selected_package)
        self._fetch_info(name)

    def _fetch_info(self, package_name: str) -> None:
        if not package_name:
            return
        if self._info_thread and self._info_thread.isRunning():
            self._pending_info_name = package_name
            return
        self._pending_info_name = None
        self._info_thread = QThread(self)
        self._info_worker = InfoWorker(package_name)
        self._info_worker.moveToThread(self._info_thread)
        self._info_thread.started.connect(self._info_worker.run)
        self._info_worker.infoReady.connect(self._update_selected_info)
        self._info_worker.error.connect(self._show_info_error)
        self._info_worker.finished.connect(self._info_thread.quit)
        self._info_worker.finished.connect(self._info_worker.deleteLater)
        self._info_thread.finished.connect(self._info_thread.deleteLater)
        self._info_thread.finished.connect(self._info_finished)
        self._info_thread.start()

    @Slot(str, dict)
    def _update_selected_info(self, package_name: str, info: dict[str, Any]) -> None:
        if not self._selected_package or self._selected_package.get("Name") != package_name:
            return
        self._selected_package.update(info)
        self._render_info(self._selected_package)
        self.packageSelected.emit(self._selected_package)

    @Slot(str, str)
    def _show_info_error(self, package_name: str, message: str) -> None:
        if self._selected_package and self._selected_package.get("Name") == package_name:
            self._set_status(
                self.tr("Pacote selecionado, mas os detalhes completos não foram carregados: {error}").format(
                    error=message
                )
            )

    @Slot()
    def _info_finished(self) -> None:
        self._info_thread = None
        self._info_worker = None
        pending = self._pending_info_name
        self._pending_info_name = None
        if pending and self._selected_package and self._selected_package.get("Name") == pending:
            self._fetch_info(pending)

    def _render_info(self, package: dict[str, Any] | None) -> None:
        if not package:
            self.info_browser.setHtml(
                "<p style='color:#9ca3af'>"
                + html.escape(
                    self.tr("Selecione um resultado para ver versão, mantenedor, URL, licença e link AUR.")
                )
                + "</p>"
            )
            return
        name = str(package.get("Name", ""))
        aur_url = f"https://aur.archlinux.org/packages/{quote(name)}" if name else ""
        lines = [
            f"<h3>{html.escape(name or self.tr('Pacote'))}</h3>",
            f"<p>{html.escape(str(package.get('Description') or self.tr('Sem descrição.')))}</p>",
            "<table>",
            self._row(self.tr("Versão"), package.get("Version")),
            self._row(self.tr("Mantenedor"), package.get("Maintainer") or self.tr("(sem mantenedor)")),
            self._row("URL", self._link(package.get("URL")), trusted_html=True),
            self._row(self.tr("Licença"), self._format_list(package.get("License")), trusted_html=True),
            self._row(self.tr("Última modificação"), format_unix_timestamp(package.get("LastModified"))),
            self._row(self.tr("Votos"), package.get("NumVotes")),
            self._row(self.tr("Popularidade"), f"{float(package.get('Popularity') or 0):.6f}"),
            self._row(self.tr("Link AUR"), self._link(aur_url, self.tr("Abrir página AUR")), trusted_html=True),
            "</table>",
        ]
        self.info_browser.setHtml("".join(lines))

    def _row(self, label: str, value: object, trusted_html: bool = False) -> str:
        rendered = str(value) if value not in (None, "") else self.tr("Não disponível")
        if not trusted_html:
            rendered = html.escape(rendered)
        return (
            "<tr>"
            f"<td style='padding:2px 10px 2px 0;color:#9ca3af'>{html.escape(label)}</td>"
            f"<td style='padding:2px 0'>{rendered}</td>"
            "</tr>"
        )

    def _link(self, url: object, label: str | None = None) -> str:
        if not url:
            return self.tr("Não disponível")
        raw = str(url)
        return f"<a href='{html.escape(raw, quote=True)}'>{html.escape(label or raw)}</a>"

    def _format_list(self, value: object) -> str:
        if isinstance(value, list):
            return html.escape(", ".join(str(item) for item in value) or self.tr("Não disponível"))
        if isinstance(value, tuple):
            return html.escape(", ".join(str(item) for item in value) or self.tr("Não disponível"))
        return html.escape(str(value)) if value else self.tr("Não disponível")

    def _set_status(self, message: str) -> None:
        self.status_label.setText(message)
        self.statusChanged.emit(message)
