from __future__ import annotations

import shlex
import shutil
from pathlib import Path
from typing import Any

from PySide6.QtCore import QProcess, QSize, Qt, QThread, QUrl, Signal, Slot
from PySide6.QtGui import QAction, QActionGroup, QDesktopServices, QFont, QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QStyle,
    QToolBar,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from aur_sentinel.audit.aur_audit_runner import (
    AurAuditResult,
    AurAuditRunner,
    AurAuditStatus,
    generate_ai_report,
)
from aur_sentinel.i18n import EN_US, PT_BR, apply_language, current_language, save_language
from aur_sentinel.ui.dialogs import HelpDialog, WhyDialog
from aur_sentinel.ui.package_search import PackageSearchWidget
from aur_sentinel.utils.paths import downloads_dir


class MainWindow(QMainWindow):
    cancelAuditRequested = Signal()

    def __init__(self) -> None:
        super().__init__()
        self.resize(1180, 840)
        self.current_result = AurAuditResult()
        self.selected_package_info: dict[str, Any] | None = None
        self.audit_thread: QThread | None = None
        self.audit_runner: AurAuditRunner | None = None
        self.install_process: QProcess | None = None
        self._build_toolbar()
        self._build_ui()
        self._apply_style()
        self.retranslateUi()
        self._render_result(self.current_result)

    def _build_toolbar(self) -> None:
        self.toolbar = QToolBar(self)
        self.toolbar.setObjectName("TopToolbar")
        self.toolbar.setMovable(False)
        self.toolbar.setIconSize(QSize(18, 18))
        self.toolbar.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.addToolBar(Qt.TopToolBarArea, self.toolbar)

        self.open_downloads_action = QAction(
            self.style().standardIcon(QStyle.SP_DirOpenIcon),
            "",
            self,
        )
        self.open_downloads_action.triggered.connect(self.open_downloads)
        self.toolbar.addAction(self.open_downloads_action)

        self.language_menu = QMenu(self)
        self.language_group = QActionGroup(self)
        self.language_group.setExclusive(True)
        self.language_pt_action = QAction("Português (Brasil)", self)
        self.language_pt_action.setCheckable(True)
        self.language_pt_action.setData(PT_BR)
        self.language_en_action = QAction("English (US)", self)
        self.language_en_action.setCheckable(True)
        self.language_en_action.setData(EN_US)
        for action in (self.language_pt_action, self.language_en_action):
            self.language_group.addAction(action)
            self.language_menu.addAction(action)
            action.triggered.connect(lambda _checked=False, action=action: self.change_language(str(action.data())))
        self.language_button = QToolButton(self)
        self.language_button.setIcon(self.style().standardIcon(QStyle.SP_FileDialogDetailedView))
        self.language_button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.language_button.setPopupMode(QToolButton.InstantPopup)
        self.language_button.setMenu(self.language_menu)
        self.toolbar.addWidget(self.language_button)

        self.help_menu = QMenu(self)
        self.protects_action = QAction(self)
        self.checks_action = QAction(self)
        self.protects_action.triggered.connect(lambda _checked=False: self.show_help(0))
        self.checks_action.triggered.connect(lambda _checked=False: self.show_help(1))
        self.help_menu.addAction(self.protects_action)
        self.help_menu.addAction(self.checks_action)
        self.help_button = QToolButton(self)
        self.help_button.setIcon(self.style().standardIcon(QStyle.SP_DialogHelpButton))
        self.help_button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.help_button.setPopupMode(QToolButton.InstantPopup)
        self.help_button.setMenu(self.help_menu)
        self.toolbar.addWidget(self.help_button)

        self.copy_ai_action = QAction(
            self.style().standardIcon(QStyle.SP_DialogSaveButton),
            "",
            self,
        )
        self.copy_ai_action.triggered.connect(self.copy_ai_report)
        self.copy_ai_action.setEnabled(False)
        self.toolbar.addAction(self.copy_ai_action)

        self.install_action = QAction(
            self.style().standardIcon(QStyle.SP_DialogApplyButton),
            "",
            self,
        )
        self.install_action.triggered.connect(self.install_audited_package)
        self.install_action.setEnabled(False)
        self.toolbar.addAction(self.install_action)

    def _build_ui(self) -> None:
        root = QWidget()
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(16, 14, 16, 14)
        root_layout.setSpacing(12)
        self.setCentralWidget(root)

        header = QFrame()
        header.setObjectName("Header")
        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(0, 0, 0, 6)
        header_layout.setSpacing(2)

        self.title_label = QLabel()
        self.title_label.setObjectName("WindowTitle")
        self.subtitle_label = QLabel()
        self.subtitle_label.setObjectName("MutedLabel")
        self.subtitle_label.setWordWrap(True)
        header_layout.addWidget(self.title_label)
        header_layout.addWidget(self.subtitle_label)
        root_layout.addWidget(header)

        self.package_search = PackageSearchWidget()
        self.package_edit = self.package_search.search_edit
        self.package_search.packageSelected.connect(self._on_package_selected)
        self.package_search.statusChanged.connect(self._show_search_status)
        root_layout.addWidget(self.package_search, 0)

        audit_row = QHBoxLayout()
        audit_row.setSpacing(8)
        self.selected_label = QLabel()
        self.selected_label.setObjectName("MutedLabel")
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setMaximumWidth(180)
        self.progress_bar.setVisible(False)
        self.audit_button = QPushButton()
        self.audit_button.setObjectName("PrimaryButton")
        self.audit_button.clicked.connect(self.start_audit)
        self.audit_button.setEnabled(False)
        self.cancel_button = QPushButton()
        self.cancel_button.clicked.connect(self.cancel_audit)
        self.cancel_button.setVisible(False)
        audit_row.addWidget(self.selected_label, 1)
        audit_row.addWidget(self.progress_bar)
        audit_row.addWidget(self.audit_button)
        audit_row.addWidget(self.cancel_button)
        root_layout.addLayout(audit_row)

        self.result_card = QFrame()
        self.result_card.setObjectName("ResultCard")
        self.result_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        result_layout = QVBoxLayout(self.result_card)
        result_layout.setContentsMargins(16, 14, 16, 14)
        result_layout.setSpacing(8)

        result_header = QHBoxLayout()
        self.result_title = QLabel()
        self.result_title.setObjectName("ResultTitle")
        self.result_title.setWordWrap(True)
        self.why_button = QPushButton()
        self.why_button.setObjectName("LinkButton")
        self.why_button.clicked.connect(self.show_why)
        self.why_button.setVisible(False)
        result_header.addWidget(self.result_title, 1)
        result_header.addWidget(self.why_button, 0, Qt.AlignTop)

        self.result_message = QLabel()
        self.result_message.setObjectName("ResultMessage")
        self.result_message.setWordWrap(True)
        self.result_detail = QLabel()
        self.result_detail.setObjectName("ResultDetail")
        self.result_detail.setWordWrap(True)
        result_layout.addLayout(result_header)
        result_layout.addWidget(self.result_message)
        result_layout.addWidget(self.result_detail)
        root_layout.addWidget(self.result_card)

        log_header = QHBoxLayout()
        self.log_title = QLabel()
        self.log_title.setObjectName("PanelTitle")
        self.copy_ai_button = QPushButton()
        self.copy_ai_button.clicked.connect(self.copy_ai_report)
        self.copy_ai_button.setEnabled(False)
        log_header.addWidget(self.log_title, 1)
        log_header.addWidget(self.copy_ai_button)
        root_layout.addLayout(log_header)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setLineWrapMode(QPlainTextEdit.NoWrap)
        mono = QFont("monospace")
        mono.setStyleHint(QFont.Monospace)
        self.log_view.setFont(mono)
        root_layout.addWidget(self.log_view, 1)

        self.status_bar = self.statusBar()
        self.status_bar.showMessage("")

    def retranslateUi(self) -> None:
        self.setWindowTitle(self.tr("Aur Sentinel"))
        self.toolbar.setWindowTitle(self.tr("Ações"))
        self.open_downloads_action.setText(self.tr("Abrir Downloads"))
        self.language_button.setText(self.tr("Idioma"))
        self.help_button.setText(self.tr("Ajuda"))
        self.protects_action.setText(self.tr("Do que o Aur Sentinel protege?"))
        self.checks_action.setText(self.tr("Como ele verifica?"))
        self.copy_ai_action.setText(self.tr("Copiar para IA"))
        self.install_action.setText(self.tr("Instalar"))
        self.title_label.setText(self.tr("Aur Sentinel"))
        self.subtitle_label.setText(
            self.tr("Auditoria AUR antes do makepkg, focada em padrões de incidentes documentados.")
        )
        self.audit_button.setText(self.tr("Auditar"))
        self.cancel_button.setText(self.tr("Cancelar"))
        self.why_button.setText(self.tr("Por quê?"))
        self.log_title.setText(self.tr("Log técnico"))
        self.copy_ai_button.setText(self.tr("Copiar para IA"))
        self.package_search.retranslateUi()
        self._sync_language_actions()
        self._update_selected_label()
        self._render_result(self.current_result)
        if not self.status_bar.currentMessage():
            self.status_bar.showMessage(self.tr("Pronto para auditar"))

    @Slot(str)
    def change_language(self, language: str) -> None:
        selected = apply_language(language)
        save_language(selected)
        self.retranslateUi()
        self.status_bar.showMessage(self.tr("O idioma foi alterado."))

    def _sync_language_actions(self) -> None:
        selected = current_language()
        self.language_pt_action.setChecked(selected == PT_BR)
        self.language_en_action.setChecked(selected == EN_US)

    @Slot()
    def open_downloads(self) -> None:
        path = downloads_dir()
        path.mkdir(parents=True, exist_ok=True)
        if not QDesktopServices.openUrl(QUrl.fromLocalFile(str(path))):
            QMessageBox.warning(
                self,
                self.tr("Aur Sentinel"),
                self.tr("Não foi possível abrir o diretório:\n{path}").format(path=path),
            )

    @Slot()
    def show_help(self, page: int = 0) -> None:
        dialog = HelpDialog(page, self)
        dialog.exec()

    @Slot()
    def show_why(self) -> None:
        dialog = WhyDialog(self.current_result, self)
        dialog.exec()

    @Slot(dict)
    def _on_package_selected(self, package: dict[str, Any]) -> None:
        if not package:
            self.selected_package_info = None
            self._update_selected_label()
            self._update_button_state()
            return
        package_name = str(package.get("Name", "")).strip()
        previous_result_package = self.current_result.packageName
        self.selected_package_info = dict(package)
        self._update_selected_label()
        if (
            previous_result_package
            and previous_result_package != package_name
            and self.current_result.status not in {AurAuditStatus.NotStarted, AurAuditStatus.Running}
        ):
            self.current_result = AurAuditResult(packageName=package_name, packageInfo=dict(package))
            self.log_view.clear()
            self._render_result(self.current_result)
        self._update_button_state()

    @Slot(str)
    def _show_search_status(self, message: str) -> None:
        if not self._is_running():
            self.status_bar.showMessage(message)

    @Slot()
    def start_audit(self) -> None:
        if self._is_running():
            self.status_bar.showMessage(self.tr("Auditoria em andamento."))
            return
        package = self.selected_package_info
        package_name = str(package.get("Name", "")).strip() if package else ""
        if not package_name:
            QMessageBox.information(
                self,
                self.tr("Aur Sentinel"),
                self.tr("Busque um pacote AUR e selecione um resultado antes de auditar."),
            )
            self.status_bar.showMessage(self.tr("Selecione um pacote para auditar."))
            return

        self.log_view.clear()
        self.current_result = AurAuditResult(
            packageName=package_name,
            packageInfo=dict(package or {}),
            status=AurAuditStatus.Running,
            statusTitle=self.tr("Auditoria em andamento"),
            statusMessage=self.tr("Coletando dados do pacote AUR."),
        )
        self._render_result(self.current_result)
        self._set_running(True)
        self.status_bar.showMessage(self.tr("Auditando {package}...").format(package=package_name))

        thread = QThread(self)
        runner = AurAuditRunner(package_name, package_info=package, language=current_language())
        runner.moveToThread(thread)
        thread.started.connect(runner.run)
        runner.logMessage.connect(self._append_log)
        runner.resultUpdated.connect(self._render_result)
        runner.finished.connect(self._audit_finished)
        runner.finished.connect(thread.quit)
        runner.finished.connect(runner.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(self._audit_thread_finished)
        self.cancelAuditRequested.connect(runner.cancel)

        self.audit_thread = thread
        self.audit_runner = runner
        thread.start()

    @Slot()
    def cancel_audit(self) -> None:
        if not self._is_running():
            return
        self.cancel_button.setEnabled(False)
        self.status_bar.showMessage(self.tr("Cancelando auditoria..."))
        self.cancelAuditRequested.emit()

    @Slot()
    def copy_ai_report(self) -> None:
        report = generate_ai_report(self.current_result)
        if not report:
            QMessageBox.information(
                self,
                self.tr("Aur Sentinel"),
                self.tr("Nenhum relatório de auditoria disponível para copiar."),
            )
            return
        QApplication.clipboard().setText(report)
        self.status_bar.showMessage(self.tr("Relatório Markdown copiado para a área de transferência."))

    @Slot()
    def install_audited_package(self) -> None:
        packages = self._audited_package_files()
        if not self._can_install(packages):
            QMessageBox.information(
                self,
                self.tr("Aur Sentinel"),
                self.tr("A instalação só é liberada quando a auditoria atual terminou em OK para o pacote selecionado."),
            )
            self._update_button_state()
            return
        package_names = "\n".join(f"- {path.name}" for path in packages)
        reply = QMessageBox.question(
            self,
            self.tr("Instalar pacote auditado?"),
            (
                self.tr(
                    "O pacote foi auditado e classificado como OK. Deseja instalar os arquivos gerados nesta auditoria?"
                )
                + f"\n\n{package_names}"
            ),
            QMessageBox.Yes | QMessageBox.Cancel,
            QMessageBox.Cancel,
        )
        if reply != QMessageBox.Yes:
            return

        command = self._install_command(packages)
        if command is None:
            QMessageBox.warning(
                self,
                self.tr("Erro na instalação"),
                self.tr("Não encontrei pkexec, kdesu ou kdesudo para executar pacman com privilégio."),
            )
            return
        program, arguments, display_command = command
        self._append_log("\n== " + self.tr("Instalação do pacote auditado") + " ==\n")
        self._append_log(f"$ {display_command}\n")

        process = QProcess(self)
        process.setProgram(program)
        process.setArguments(arguments)
        process.setProcessChannelMode(QProcess.MergedChannels)
        process.readyReadStandardOutput.connect(self._append_install_output)
        process.readyReadStandardError.connect(self._append_install_output)
        process.finished.connect(self._install_finished)
        process.errorOccurred.connect(self._install_error)
        self.install_process = process
        self._update_button_state()
        process.start()
        if not process.waitForStarted(3000):
            message = process.errorString() or self.tr("Falha ao iniciar o processo de instalação.")
            self._append_log(message + "\n")
            self.install_process = None
            self._update_button_state()
            QMessageBox.warning(self, self.tr("Erro na instalação"), message)

    @Slot(str)
    def _append_log(self, text: str) -> None:
        self.log_view.moveCursor(QTextCursor.End)
        self.log_view.insertPlainText(text)
        self.log_view.moveCursor(QTextCursor.End)

    @Slot()
    def _append_install_output(self) -> None:
        process = self.install_process
        if not process:
            return
        data = bytes(process.readAll()).decode("utf-8", errors="replace")
        if data:
            self._append_log(data)

    @Slot(int, QProcess.ExitStatus)
    def _install_finished(self, exit_code: int, _exit_status: QProcess.ExitStatus) -> None:
        self._append_install_output()
        self.install_process = None
        self._update_button_state()
        if exit_code == 0:
            self.status_bar.showMessage(self.tr("Instalação concluída."))
            QMessageBox.information(self, self.tr("Aur Sentinel"), self.tr("Instalação concluída."))
        else:
            self.status_bar.showMessage(self.tr("Erro operacional durante instalação."))
            QMessageBox.warning(
                self,
                self.tr("Erro na instalação"),
                self.tr("A instalação falhou. Veja o log técnico para os detalhes."),
            )

    @Slot(QProcess.ProcessError)
    def _install_error(self, _error: QProcess.ProcessError) -> None:
        process = self.install_process
        if not process:
            return
        message = process.errorString()
        self._append_log(message + "\n")
        if _error == QProcess.FailedToStart:
            self.install_process = None
            self._update_button_state()
            QMessageBox.warning(self, self.tr("Erro na instalação"), message)

    @Slot(object)
    def _render_result(self, result: AurAuditResult) -> None:
        self.current_result = result
        self.result_title.setText(self._status_title(result))
        self.result_message.setText(self._status_message(result))
        self.result_detail.setText(self._detail_text(result))
        self.why_button.setVisible(result.status in {AurAuditStatus.Ok, AurAuditStatus.Blocked, AurAuditStatus.OperationalError})
        self.copy_ai_action.setEnabled(bool(result.aiReport))
        self.copy_ai_button.setEnabled(bool(result.aiReport))
        self._apply_result_style(result.status)
        self._update_button_state()

    @Slot(object)
    def _audit_finished(self, result: AurAuditResult) -> None:
        self.current_result = result
        self._render_result(result)
        self._set_running(False)
        self.status_bar.showMessage(self._status_title(result))

    @Slot()
    def _audit_thread_finished(self) -> None:
        self.audit_thread = None
        self.audit_runner = None
        self._set_running(False)

    def _detail_text(self, result: AurAuditResult) -> str:
        if result.status == AurAuditStatus.Blocked:
            parts: list[str] = []
            if result.statusDetail:
                parts.append(result.statusDetail)
            if result.matchedPatterns:
                patterns = sorted({match.pattern for match in result.matchedPatterns})
                parts.append(self.tr("Padrões: {patterns}").format(patterns=", ".join(patterns)))
            if result.sensitiveFiles:
                parts.append(self.tr("Arquivos: {files}").format(files=", ".join(result.sensitiveFiles[:8])))
            return "\n".join(parts)
        return result.statusDetail

    def _update_selected_label(self) -> None:
        package_name = self._selected_package_name()
        if package_name:
            self.selected_label.setText(self.tr("Selecionado: {package}").format(package=package_name))
        else:
            self.selected_label.setText(self.tr("Nenhum pacote selecionado."))

    def _status_title(self, result: AurAuditResult) -> str:
        titles = {
            AurAuditStatus.NotStarted: self.tr("Pronto para auditar"),
            AurAuditStatus.Running: self.tr("Auditoria em andamento"),
            AurAuditStatus.Ok: self.tr("OK — pode instalar"),
            AurAuditStatus.Blocked: self.tr("INSEGURO — revisão manual necessária"),
            AurAuditStatus.OperationalError: self.tr("Erro na auditoria"),
        }
        return titles.get(result.status, result.statusTitle)

    def _status_message(self, result: AurAuditResult) -> str:
        messages = {
            AurAuditStatus.NotStarted: self.tr("Busque um pacote AUR, selecione-o na lista e clique em Auditar."),
            AurAuditStatus.Running: self.tr("Coletando dados do pacote AUR."),
            AurAuditStatus.Ok: self.tr(
                "Nenhum padrão compatível com incidentes AUR documentados foi encontrado."
            ),
            AurAuditStatus.Blocked: self.tr(
                "Foram encontrados padrões compatíveis com incidentes AUR documentados."
            ),
            AurAuditStatus.OperationalError: self.tr(
                "A auditoria não foi concluída por erro operacional, dependência ausente ou falha de build."
            ),
        }
        return messages.get(result.status, result.statusMessage)

    def _audited_package_files(self) -> list[Path]:
        result = self.current_result
        if not result.workDir or not result.packageFiles:
            return []
        try:
            work_dir = Path(result.workDir).resolve()
        except OSError:
            return []
        packages: list[Path] = []
        for raw in result.packageFiles:
            path = Path(raw)
            if path.suffixes[-3:] != [".pkg", ".tar", ".zst"] and not path.name.endswith(".pkg.tar.zst"):
                return []
            try:
                resolved = path.resolve()
                resolved.relative_to(work_dir)
            except (OSError, ValueError):
                return []
            if not resolved.is_file():
                return []
            packages.append(resolved)
        return packages

    def _can_install(self, packages: list[Path] | None = None) -> bool:
        if self._is_running() or self._is_installing():
            return False
        selected_name = self._selected_package_name()
        result = self.current_result
        package_paths = packages if packages is not None else self._audited_package_files()
        return (
            result.status == AurAuditStatus.Ok
            and bool(package_paths)
            and bool(selected_name)
            and result.packageName == selected_name
        )

    def _install_command(self, packages: list[Path]) -> tuple[str, list[str], str] | None:
        pacman_args = ["pacman", "-U", "--needed", "--noconfirm", "--", *[str(path) for path in packages]]
        pkexec = shutil.which("pkexec")
        if pkexec:
            return pkexec, pacman_args, "pkexec " + " ".join(shlex.quote(arg) for arg in pacman_args)
        command = " ".join(shlex.quote(arg) for arg in pacman_args)
        kdesu = shutil.which("kdesu") or shutil.which("kdesudo")
        if kdesu:
            return kdesu, ["-c", command], f"{Path(kdesu).name} -c {shlex.quote(command)}"
        return None

    def _selected_package_name(self) -> str:
        package = self.selected_package_info or self.package_search.selected_package()
        return str(package.get("Name", "")).strip() if package else ""

    def _set_running(self, running: bool) -> None:
        self.package_search.setEnabled(not running)
        self.audit_button.setEnabled(not running and bool(self._selected_package_name()))
        self.cancel_button.setVisible(running)
        self.cancel_button.setEnabled(running)
        self.progress_bar.setVisible(running)
        self._update_button_state()

    def _is_running(self) -> bool:
        return bool(self.audit_thread and self.audit_thread.isRunning())

    def _is_installing(self) -> bool:
        return bool(self.install_process and self.install_process.state() != QProcess.NotRunning)

    def _update_button_state(self) -> None:
        running = self._is_running()
        installing = self._is_installing()
        has_selection = bool(self._selected_package_name())
        has_report = bool(self.current_result.aiReport)
        can_install = self._can_install() if not running and not installing else False
        self.audit_button.setEnabled(has_selection and not running and not installing)
        self.install_action.setEnabled(can_install)
        self.copy_ai_action.setEnabled(has_report and not running)
        self.copy_ai_button.setEnabled(has_report and not running)
        if installing:
            self.status_bar.showMessage(self.tr("Instalando pacote auditado..."))

    def _apply_result_style(self, status: AurAuditStatus) -> None:
        palette = {
            AurAuditStatus.NotStarted: ("#15191f", "#2d333d", "#f3f4f6", "#cbd5d1"),
            AurAuditStatus.Running: ("#111f2a", "#2b6f8a", "#dbeafe", "#b7d4df"),
            AurAuditStatus.Ok: ("#0f251d", "#22c55e", "#86efac", "#c7f9d4"),
            AurAuditStatus.Blocked: ("#32161a", "#ef4444", "#fecaca", "#f7c2c2"),
            AurAuditStatus.OperationalError: ("#2c2414", "#f59e0b", "#fde68a", "#f6d89b"),
        }[status]
        background, border, title_color, text_color = palette
        self.result_card.setStyleSheet(
            f"""
            #ResultCard {{
                background: {background};
                border: 1px solid {border};
                border-radius: 8px;
            }}
            #ResultTitle {{
                color: {title_color};
                font-size: 15pt;
                font-weight: 700;
            }}
            #ResultMessage {{
                color: {text_color};
                font-size: 10.5pt;
            }}
            #ResultDetail {{
                color: {text_color};
                font-size: 9.5pt;
            }}
            """
        )

    def _apply_style(self) -> None:
        self.setStyleSheet(
            """
            QMainWindow, QWidget {
                background: #0f1115;
                color: #e5e7eb;
                font-size: 10pt;
            }
            QToolBar#TopToolbar {
                background: #15181d;
                border: 0;
                border-bottom: 1px solid #2a2f38;
                spacing: 6px;
                padding: 4px;
            }
            QToolButton, QPushButton {
                min-height: 32px;
                padding: 5px 12px;
                border: 1px solid #333946;
                border-radius: 6px;
                background: #1b2028;
                color: #e5e7eb;
            }
            QToolButton:hover, QPushButton:hover {
                background: #242a34;
                border-color: #4b5563;
            }
            QToolButton:disabled, QPushButton:disabled {
                color: #6b7280;
                background: #15181d;
                border-color: #272c35;
            }
            QPushButton#PrimaryButton {
                background: #0f766e;
                border-color: #14b8a6;
                color: #ecfeff;
                font-weight: 700;
            }
            QPushButton#PrimaryButton:disabled {
                background: #153532;
                border-color: #1f4a46;
                color: #829b98;
            }
            QPushButton#LinkButton {
                background: transparent;
                border: 1px solid #3a414d;
                color: #d1d5db;
                padding: 4px 10px;
            }
            #Header {
                border-bottom: 1px solid #2a2f38;
            }
            #WindowTitle {
                font-size: 18pt;
                font-weight: 700;
                color: #f9fafb;
            }
            #PanelTitle {
                font-size: 11.5pt;
                font-weight: 700;
                color: #f3f4f6;
            }
            #MutedLabel {
                color: #9ca3af;
            }
            QLineEdit {
                min-height: 34px;
                padding: 4px 8px;
                border: 1px solid #343a46;
                border-radius: 6px;
                background: #12161c;
                color: #f3f4f6;
                selection-background-color: #0f766e;
            }
            QTableWidget {
                border: 1px solid #303743;
                border-radius: 6px;
                background: #10141a;
                alternate-background-color: #141920;
                gridline-color: #29313b;
                selection-background-color: #0f766e;
                selection-color: #f9fafb;
            }
            QHeaderView::section {
                background: #171c23;
                color: #d1d5db;
                border: 0;
                border-right: 1px solid #303743;
                border-bottom: 1px solid #303743;
                padding: 5px;
            }
            QFrame#PackageInfoCard {
                border: 1px solid #303743;
                border-radius: 8px;
                background: #11161c;
            }
            QTextBrowser#PackageInfo {
                border: 0;
                background: transparent;
                color: #d1d5db;
            }
            QPlainTextEdit {
                border: 1px solid #303743;
                border-radius: 6px;
                padding: 6px;
                background: #0b0f14;
                color: #d6dde6;
                selection-background-color: #0f766e;
            }
            QProgressBar {
                border: 1px solid #303743;
                border-radius: 5px;
                background: #11161c;
            }
            QProgressBar::chunk {
                background: #14b8a6;
                border-radius: 4px;
            }
            QMenu {
                background: #15181d;
                color: #e5e7eb;
                border: 1px solid #303743;
            }
            QMenu::item:selected {
                background: #0f766e;
            }
            QStatusBar {
                background: #0f1115;
                color: #9ca3af;
            }
            """
        )
