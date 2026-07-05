from __future__ import annotations

import html
from pathlib import Path

from PySide6.QtCore import QCoreApplication
from PySide6.QtWidgets import QDialog, QDialogButtonBox, QTabWidget, QTextBrowser, QVBoxLayout, QWidget

from aur_sentinel.audit.aur_audit_runner import AurAuditResult, AurAuditStatus


def _tr(context: str, text: str) -> str:
    return QCoreApplication.translate(context, text)


class HelpDialog(QDialog):
    def __init__(self, page: int = 0, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(self.tr("Ajuda"))
        self.resize(760, 560)

        layout = QVBoxLayout(self)
        self.tabs = QTabWidget()
        self.tabs.addTab(self._page(_protects_html()), self.tr("Do que o Aur Sentinel protege?"))
        self.tabs.addTab(self._page(_checks_html()), self.tr("Como ele verifica?"))
        self.tabs.setCurrentIndex(max(0, min(page, self.tabs.count() - 1)))
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        close_button = buttons.button(QDialogButtonBox.Close)
        if close_button:
            close_button.setText(self.tr("Fechar"))
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        layout.addWidget(self.tabs, 1)
        layout.addWidget(buttons)

    def _page(self, content: str) -> QTextBrowser:
        browser = QTextBrowser()
        browser.setOpenExternalLinks(True)
        browser.setHtml(content)
        return browser


class WhyDialog(QDialog):
    def __init__(self, result: AurAuditResult, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(self.tr("Por quê?"))
        self.resize(760, 560)

        layout = QVBoxLayout(self)
        browser = QTextBrowser()
        browser.setOpenExternalLinks(True)
        browser.setHtml(_why_html(result))
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        close_button = buttons.button(QDialogButtonBox.Close)
        if close_button:
            close_button.setText(self.tr("Fechar"))
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        layout.addWidget(browser, 1)
        layout.addWidget(buttons)


def _protects_html() -> str:
    title = _tr("HelpDialog", "Do que o Aur Sentinel protege?")
    return f"""
    <h2>{title}</h2>
    <p>{_tr("HelpDialog", "O Aur Sentinel protege contra padrões compatíveis com incidentes AUR já documentados.")}</p>
    <p>{_tr("HelpDialog", "Ele verifica vetores usados em incidentes conhecidos, como:")}</p>
    <ul>
      <li>{_tr("HelpDialog", "2018: pacotes AUR com execução remota via curl | bash e download de scripts externos.")}</li>
      <li>{_tr("HelpDialog", "2025: pacotes como librewolf-fix-bin, firefox-patch-bin e zen-browser-patched-bin, associados a script remoto/RAT.")}</li>
      <li>{_tr("HelpDialog", "2026: campanhas com adoção maliciosa de pacotes órfãos e uso de npm, atomic-lockfile, lockfile-js e js-digest.")}</li>
      <li>{_tr("HelpDialog", "2026: nova onda usando bun, execa, commander e padrões similares.")}</li>
    </ul>
    <p>{_tr("HelpDialog", "Ele também verifica .install, hooks e arquivos sensíveis, systemd, udev, polkit, sudoers, Install Script, caminhos sensíveis no pacote final, setuid/setgid e Linux capabilities.")}</p>
    <p><b>{_tr("HelpDialog", "O Aur Sentinel não substitui uma auditoria completa do código upstream, mas reduz o risco ao bloquear padrões compatíveis com os incidentes AUR conhecidos.")}</b></p>
    """


def _checks_html() -> str:
    title = _tr("HelpDialog", "Como o Aur Sentinel verifica?")
    return f"""
    <h2>{title}</h2>
    <p>{_tr("HelpDialog", "O Aur Sentinel segue um fluxo fail-closed:")}</p>
    <ol>
      <li>{_tr("HelpDialog", "clona o repositório AUR do pacote na pasta Downloads;")}</li>
      <li>{_tr("HelpDialog", "lista os arquivos versionados;")}</li>
      <li>{_tr("HelpDialog", "coleta commits recentes;")}</li>
      <li>{_tr("HelpDialog", "analisa o diff do último commit;")}</li>
      <li>{_tr("HelpDialog", "procura padrões compatíveis com incidentes documentados;")}</li>
      <li>{_tr("HelpDialog", "verifica arquivos sensíveis;")}</li>
      <li>{_tr("HelpDialog", "se encontrar algo sensível, bloqueia antes do makepkg;")}</li>
      <li>{_tr("HelpDialog", "se não encontrar, valida fontes e checksums;")}</li>
      <li>{_tr("HelpDialog", "compila sem instalar;")}</li>
      <li>{_tr("HelpDialog", "inspeciona o pacote final;")}</li>
      <li>{_tr("HelpDialog", "verifica Install Script, caminhos sensíveis, setuid/setgid e capabilities;")}</li>
      <li>{_tr("HelpDialog", "classifica o resultado como OK, INSEGURO ou Erro operacional.")}</li>
    </ol>
    <p>{_tr("HelpDialog", "Verde significa que passou nos checks.")}<br>
    {_tr("HelpDialog", "Vermelho significa que foram encontrados padrões compatíveis com incidentes conhecidos.")}<br>
    {_tr("HelpDialog", "Amarelo/cinza significa erro operacional.")}</p>
    """


def _why_html(result: AurAuditResult) -> str:
    if result.status == AurAuditStatus.Ok:
        return _why_ok(result)
    if result.status == AurAuditStatus.Blocked:
        return _why_blocked(result)
    if result.status == AurAuditStatus.OperationalError:
        return _why_error(result)
    return f"""
    <h2>{_tr("WhyDialog", "Pronto para auditar")}</h2>
    <p>{_tr("WhyDialog", "Busque um pacote AUR, selecione-o na lista e clique em Auditar.")}</p>
    """


def _why_ok(result: AurAuditResult) -> str:
    return f"""
    <h2>{_tr("WhyDialog", "OK — pode instalar")}</h2>
    <p>{_tr("WhyDialog", "Você pode instalar porque o Aur Sentinel verificou os arquivos versionados do AUR, analisou o histórico recente do pacote, inspecionou o diff mais recente, bloqueou padrões compatíveis com incidentes conhecidos, validou as fontes, compilou sem instalar, analisou os metadados do pacote final e verificou que não há Install Script, caminhos sensíveis, setuid/setgid ou capabilities.")}</p>
    <ul>
      <li>{_tr("WhyDialog", "PKGBUILD analisado;")}</li>
      <li>{_tr("WhyDialog", "últimos commits analisados;")}</li>
      <li>{_tr("WhyDialog", "diff do último commit analisado;")}</li>
      <li>{_tr("WhyDialog", "padrões sensíveis não encontrados;")}</li>
      <li>{_tr("WhyDialog", "arquivos sensíveis não encontrados;")}</li>
      <li>{_tr("WhyDialog", "fontes verificadas;")}</li>
      <li>{_tr("WhyDialog", "build executado sem instalar;")}</li>
      <li>{_tr("WhyDialog", "pacote final encontrado: {packages};").format(packages=_package_list(result))}</li>
      <li><code>Install Script : No</code>;</li>
      <li>{_tr("WhyDialog", "nenhum path sensível;")}</li>
      <li>{_tr("WhyDialog", "nenhum setuid/setgid;")}</li>
      <li>{_tr("WhyDialog", "nenhuma Linux capability.")}</li>
    </ul>
    <p>{_tr("WhyDialog", "Isso não substitui uma revisão completa do código upstream, mas responde à pergunta principal: nenhum sinal compatível com os incidentes AUR conhecidos foi encontrado nesta auditoria.")}</p>
    """


def _why_blocked(result: AurAuditResult) -> str:
    sections = [
        f"<h2>{_tr('WhyDialog', 'INSEGURO — revisão manual necessária')}</h2>",
        "<p>"
        + _tr(
            "WhyDialog",
            "Você não deve instalar este pacote sem revisão manual porque o Aur Sentinel encontrou padrões compatíveis com incidentes AUR documentados. Foi detectado uso de comandos ou arquivos sensíveis, como npm, bun, .install, scripts remotos ou outros vetores já vistos em campanhas maliciosas. Recomendo usar o botão Copiar para IA para uma análise mais avançada.",
        )
        + "</p>",
    ]
    if result.blockReason or result.statusDetail:
        sections.append(
            f"<p><b>{_tr('WhyDialog', 'Motivo:')}</b> "
            f"{html.escape(result.blockReason or result.statusDetail)}</p>"
        )
    if result.matchedPatterns:
        sections.append(f"<h3>{_tr('WhyDialog', 'Padrões encontrados')}</h3><ul>")
        for match in result.matchedPatterns:
            sections.append(
                "<li>"
                + _tr(
                    "WhyDialog",
                    "Foi encontrado o padrão {pattern} no arquivo {file}, linha {line}. Trecho: {snippet}. {reason}",
                ).format(
                    pattern=f"<code>{html.escape(match.pattern)}</code>",
                    file=f"<code>{html.escape(match.file_path)}</code>",
                    line=match.line,
                    snippet=f"<code>{html.escape(match.text)}</code>",
                    reason=html.escape(_sensitivity_reason(match.pattern)),
                )
                + "</li>"
            )
        sections.append("</ul>")
    if result.sensitiveFiles:
        sections.append(f"<h3>{_tr('WhyDialog', 'Arquivos sensíveis encontrados')}</h3><ul>")
        for item in result.sensitiveFiles:
            sections.append(f"<li><code>{html.escape(item)}</code></li>")
        sections.append("</ul>")
    if not result.matchedPatterns and not result.sensitiveFiles:
        sections.append(
            "<p>"
            + _tr(
                "WhyDialog",
                "O bloqueio veio de um check posterior, como Install Script, paths sensíveis ou permissões especiais no pacote final.",
            )
            + "</p>"
        )
    return "".join(sections)


def _why_error(result: AurAuditResult) -> str:
    details = html.escape(result.operationalError or result.statusDetail or _tr("WhyDialog", "Não disponível"))
    return f"""
    <h2>{_tr("WhyDialog", "Erro na auditoria")}</h2>
    <p>{_tr("WhyDialog", "A auditoria não foi concluída por erro operacional, dependência ausente ou falha de build. Isso não classifica o pacote como seguro nem inseguro.")}</p>
    <p><b>{_tr("WhyDialog", "Detalhes:")}</b> {details}</p>
    <p>{_tr("WhyDialog", "Corrija a dependência, rede ou falha indicada no log técnico e execute a auditoria novamente.")}</p>
    """


def _sensitivity_reason(pattern: str) -> str:
    lower = pattern.lower()
    if "npm" in lower or "atomic-lockfile" in lower or "lockfile-js" in lower or "js-digest" in lower:
        return _tr(
            "WhyDialog",
            "Esse tipo de comando foi usado em incidentes AUR documentados em 2026, como as campanhas envolvendo atomic-lockfile, js-digest e lockfile-js.",
        )
    if "bun" in lower or "execa" in lower or "commander" in lower:
        return _tr(
            "WhyDialog",
            "Esse padrão é sensível porque pode baixar ou executar dependências JavaScript durante build/install.",
        )
    if "curl" in lower or "wget" in lower:
        return _tr(
            "WhyDialog",
            "Esse padrão é sensível porque pode baixar ou executar scripts remotos antes de uma revisão local.",
        )
    if "install" in lower:
        return _tr(
            "WhyDialog",
            "Arquivos ou diretivas .install rodam durante instalação/upgrade e precisam de revisão manual.",
        )
    if lower in {"systemctl", "polkit", "sudoers", "udev", "setcap"}:
        return _tr("WhyDialog", "Esse padrão pode alterar persistência, permissões ou integração privilegiada do sistema.")
    return _tr("WhyDialog", "Esse padrão é sensível no contexto de PKGBUILD porque pode alterar o fluxo de build/install.")


def _package_list(result: AurAuditResult) -> str:
    if not result.packageFiles:
        return _tr("WhyDialog", "nenhum arquivo listado")
    return ", ".join(html.escape(Path(path).name) for path in result.packageFiles)
