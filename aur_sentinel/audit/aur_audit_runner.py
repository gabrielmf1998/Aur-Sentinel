from __future__ import annotations

import fnmatch
import os
import re
import shutil
import stat
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from PySide6.QtCore import QCoreApplication, QEventLoop, QObject, QProcess, QProcessEnvironment, QTimer, Signal, Slot

from aur_sentinel.i18n import current_language, normalize_language
from aur_sentinel.utils.paths import downloads_dir
from aur_sentinel.utils.timefmt import format_unix_timestamp


class AurAuditStatus(Enum):
    NotStarted = "NotStarted"
    Running = "Running"
    Ok = "Ok"
    Blocked = "Blocked"
    OperationalError = "OperationalError"


@dataclass(frozen=True)
class IncidentPattern:
    label: str
    grep_regex: str
    python_regex: str


@dataclass
class IncidentPatternMatch:
    pattern: str
    file_path: str
    line: int
    text: str

    def display(self) -> str:
        return f"{self.file_path}:{self.line}: [{self.pattern}] {self.text}"


@dataclass
class AurAuditResult:
    packageName: str = ""
    packageInfo: dict[str, Any] = field(default_factory=dict)
    workDir: str = ""
    status: AurAuditStatus = AurAuditStatus.NotStarted
    statusTitle: str = "Pronto para auditar"
    statusMessage: str = "Busque um pacote AUR, selecione-o na lista e clique em Auditar."
    statusDetail: str = ""
    blockReason: str = ""
    operationalError: str = ""
    matchedPatterns: list[IncidentPatternMatch] = field(default_factory=list)
    sensitiveFiles: list[str] = field(default_factory=list)
    gitFiles: list[str] = field(default_factory=list)
    gitHistory: str = ""
    lastDiff: str = ""
    pkgbuildSummary: str = ""
    verifySourceOutput: str = ""
    buildOutput: str = ""
    packageFiles: list[str] = field(default_factory=list)
    pacmanInfoOutput: str = ""
    pacmanListOutput: str = ""
    installScriptChecks: str = ""
    sensitivePathChecks: str = ""
    specialPermissionsOutput: str = ""
    aiReport: str = ""
    auditDateTime: str = ""
    logText: str = ""


@dataclass
class ProcessRun:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    failed_to_start: bool = False

    @property
    def output(self) -> str:
        if self.stderr:
            return self.stdout + ("\n" if self.stdout and not self.stdout.endswith("\n") else "") + self.stderr
        return self.stdout


class AuditOperationalError(RuntimeError):
    pass


class AuditCancelled(RuntimeError):
    pass


def _report_tr(text: str) -> str:
    return QCoreApplication.translate("AiReport", text)


def generate_ai_report(result: AurAuditResult) -> str:
    if result.status == AurAuditStatus.NotStarted and not result.packageName:
        return ""

    result_label = {
        AurAuditStatus.Ok: _report_tr("OK"),
        AurAuditStatus.Blocked: _report_tr("INSEGURO"),
        AurAuditStatus.OperationalError: _report_tr("ERRO OPERACIONAL"),
        AurAuditStatus.Running: _report_tr("EM ANDAMENTO"),
        AurAuditStatus.NotStarted: _report_tr("NÃO INICIADO"),
    }[result.status]
    reason = result.blockReason or result.operationalError or result.statusDetail or _ok_reason_text()
    final_checks = "\n\n".join(
        [
            "Install Script\n" + (result.installScriptChecks or _report_tr("(não executado)")),
            _report_tr("Caminhos sensíveis")
            + "\n"
            + (result.sensitivePathChecks or _report_tr("(não executado)")),
            "setuid/setgid/capabilities\n" + (result.specialPermissionsOutput or _report_tr("(não executado)")),
        ]
    )
    sections = [
        f"# {_report_tr('Relatório de auditoria AUR')}",
        "",
        _report_tr(
            "Analise este relatório AUR. Verifique se o pacote apresenta sinais compatíveis com incidentes AUR conhecidos, scripts remotos, hooks perigosos, persistência, caminhos sensíveis, permissões especiais ou necessidade de revisão manual."
        ),
        "",
        f"## {_report_tr('Pacote')}",
        _package_metadata_markdown(result),
        "",
        f"## {_report_tr('Data/hora')}",
        f"`{result.auditDateTime or _report_tr('Não disponível')}`",
        "",
        f"## {_report_tr('Diretório de trabalho')}",
        f"`{result.workDir or _report_tr('(não criado)')}`",
        "",
        f"## {_report_tr('Status final')}",
        f"**{result_label}**",
        "",
        f"## {_report_tr('Motivo')}",
        reason,
        "",
        f"## {_report_tr('Padrões encontrados')}",
        _list_or_none(match.display() for match in result.matchedPatterns),
        "",
        f"## {_report_tr('Arquivos sensíveis encontrados')}",
        _list_or_none(result.sensitiveFiles),
        "",
        _code_section(_report_tr("Histórico recente"), result.gitHistory),
        _code_section(_report_tr("Diff do último commit"), result.lastDiff),
        _code_section(_report_tr("Resumo do PKGBUILD"), result.pkgbuildSummary),
        _code_section(_report_tr("Validação de fontes"), result.verifySourceOutput or _report_tr("(não executado)")),
        _code_section(_report_tr("Build sem instalar"), result.buildOutput or _report_tr("(não executado)")),
        _code_section(_report_tr("Metadados do pacote final"), result.pacmanInfoOutput or _report_tr("(não executado)")),
        _code_section(
            _report_tr("Arquivos instalados pelo pacote"),
            result.pacmanListOutput or _report_tr("(não executado)"),
        ),
        _code_section(_report_tr("Checks finais"), final_checks),
        f"## {_report_tr('Conclusão')}",
        reason,
        "",
    ]
    return "\n".join(sections)


def _ok_reason_text() -> str:
    return _report_tr(
        "clone OK; arquivos versionados, commits e diff coletados; nenhum padrão sensível encontrado; makepkg --verifysource OK; makepkg -sr OK; pacote final inspecionado sem Install Script, paths sensíveis, setuid/setgid ou capabilities."
    )


def _list_or_none(items: object) -> str:
    values = list(items) if not isinstance(items, list) else items
    if not values:
        return "- " + _report_tr("Nenhum.")
    return "\n".join(f"- {value}" for value in values)


def _code_section(title: str, text: str) -> str:
    return f"## {title}\n\n```text\n{text.rstrip()}\n```"


def _package_metadata_markdown(result: AurAuditResult) -> str:
    info = result.packageInfo or {}
    lines = [f"- {_report_tr('Nome')}: {result.packageName or _report_tr('Não disponível')}"]
    if info:
        fields = (
            (_report_tr("Versão"), "Version"),
            (_report_tr("Descrição"), "Description"),
            (_report_tr("Mantenedor"), "Maintainer"),
            ("URL", "URL"),
            (_report_tr("Licença"), "License"),
            (_report_tr("Primeiro envio"), "FirstSubmitted"),
            (_report_tr("Última modificação"), "LastModified"),
            (_report_tr("Votos"), "NumVotes"),
            (_report_tr("Popularidade"), "Popularity"),
        )
        lines.extend(f"- {label}: {_metadata_value(info.get(key), key)}" for label, key in fields)
    name = str(info.get("Name") or result.packageName or "")
    if name:
        lines.append(f"- {_report_tr('Link AUR')}: https://aur.archlinux.org/packages/{name}")
    return "\n".join(lines)


def _metadata_value(value: object, key: str = "") -> str:
    if key in {"FirstSubmitted", "LastModified", "OutOfDate"}:
        formatted = format_unix_timestamp(value)  # type: ignore[arg-type]
        if formatted:
            return formatted
    if isinstance(value, list):
        return ", ".join(str(item) for item in value) or _report_tr("Não disponível")
    if value in (None, ""):
        return _report_tr("Não disponível")
    return str(value)


PKGBUILD_FIELDS = (
    "pkgbase",
    "pkgname",
    "pkgver",
    "pkgrel",
    "pkgdesc",
    "arch",
    "url",
    "license",
    "depends",
    "makedepends",
    "checkdepends",
    "optdepends",
    "provides",
    "conflicts",
    "replaces",
    "install",
    "source",
    "sha256sums",
    "b2sums",
    "validpgpkeys",
)


INCIDENT_PATTERNS = (
    IncidentPattern("atomic-lockfile", r"atomic-lockfile", r"atomic-lockfile"),
    IncidentPattern("lockfile-js", r"lockfile-js", r"lockfile-js"),
    IncidentPattern("js-digest", r"js-digest", r"js-digest"),
    IncidentPattern("nextfile-js", r"nextfile-js", r"nextfile-js"),
    IncidentPattern("bun add", r"(^|[^[:alnum:]_-])bun[[:space:]]+add([^[:alnum:]_-]|$)", r"(?<![\w-])bun\s+add(?![\w-])"),
    IncidentPattern("bun install", r"(^|[^[:alnum:]_-])bun[[:space:]]+install([^[:alnum:]_-]|$)", r"(?<![\w-])bun\s+install(?![\w-])"),
    IncidentPattern("bun x", r"(^|[^[:alnum:]_-])bun[[:space:]]+x([^[:alnum:]_-]|$)", r"(?<![\w-])bun\s+x(?![\w-])"),
    IncidentPattern("bun run", r"(^|[^[:alnum:]_-])bun[[:space:]]+run([^[:alnum:]_-]|$)", r"(?<![\w-])bun\s+run(?![\w-])"),
    IncidentPattern("npm i", r"(^|[^[:alnum:]_-])npm[[:space:]]+i([^[:alnum:]_-]|$)", r"(?<![\w-])npm\s+i(?![\w-])"),
    IncidentPattern("npm install", r"(^|[^[:alnum:]_-])npm[[:space:]]+install([^[:alnum:]_-]|$)", r"(?<![\w-])npm\s+install(?![\w-])"),
    IncidentPattern("npm add", r"(^|[^[:alnum:]_-])npm[[:space:]]+add([^[:alnum:]_-]|$)", r"(?<![\w-])npm\s+add(?![\w-])"),
    IncidentPattern("npm exec", r"(^|[^[:alnum:]_-])npm[[:space:]]+exec([^[:alnum:]_-]|$)", r"(?<![\w-])npm\s+exec(?![\w-])"),
    IncidentPattern("npm x", r"(^|[^[:alnum:]_-])npm[[:space:]]+x([^[:alnum:]_-]|$)", r"(?<![\w-])npm\s+x(?![\w-])"),
    IncidentPattern("npm run", r"(^|[^[:alnum:]_-])npm[[:space:]]+run([^[:alnum:]_-]|$)", r"(?<![\w-])npm\s+run(?![\w-])"),
    IncidentPattern("npx", r"(^|[^[:alnum:]_-])npx([^[:alnum:]_-]|$)", r"(?<![\w-])npx(?![\w-])"),
    IncidentPattern("pnpm add", r"(^|[^[:alnum:]_-])pnpm[[:space:]]+add([^[:alnum:]_-]|$)", r"(?<![\w-])pnpm\s+add(?![\w-])"),
    IncidentPattern("pnpm install", r"(^|[^[:alnum:]_-])pnpm[[:space:]]+install([^[:alnum:]_-]|$)", r"(?<![\w-])pnpm\s+install(?![\w-])"),
    IncidentPattern("pnpm exec", r"(^|[^[:alnum:]_-])pnpm[[:space:]]+exec([^[:alnum:]_-]|$)", r"(?<![\w-])pnpm\s+exec(?![\w-])"),
    IncidentPattern("pnpm dlx", r"(^|[^[:alnum:]_-])pnpm[[:space:]]+dlx([^[:alnum:]_-]|$)", r"(?<![\w-])pnpm\s+dlx(?![\w-])"),
    IncidentPattern("pnpm run", r"(^|[^[:alnum:]_-])pnpm[[:space:]]+run([^[:alnum:]_-]|$)", r"(?<![\w-])pnpm\s+run(?![\w-])"),
    IncidentPattern("yarn add", r"(^|[^[:alnum:]_-])yarn[[:space:]]+add([^[:alnum:]_-]|$)", r"(?<![\w-])yarn\s+add(?![\w-])"),
    IncidentPattern("yarn install", r"(^|[^[:alnum:]_-])yarn[[:space:]]+install([^[:alnum:]_-]|$)", r"(?<![\w-])yarn\s+install(?![\w-])"),
    IncidentPattern("yarn exec", r"(^|[^[:alnum:]_-])yarn[[:space:]]+exec([^[:alnum:]_-]|$)", r"(?<![\w-])yarn\s+exec(?![\w-])"),
    IncidentPattern("yarn dlx", r"(^|[^[:alnum:]_-])yarn[[:space:]]+dlx([^[:alnum:]_-]|$)", r"(?<![\w-])yarn\s+dlx(?![\w-])"),
    IncidentPattern("yarn run", r"(^|[^[:alnum:]_-])yarn[[:space:]]+run([^[:alnum:]_-]|$)", r"(?<![\w-])yarn\s+run(?![\w-])"),
    IncidentPattern("node ", r"(^|[^[:alnum:]_-])node[[:space:]]+", r"(?<![\w-])node\s+"),
    IncidentPattern("deno ", r"(^|[^[:alnum:]_-])deno[[:space:]]+", r"(?<![\w-])deno\s+"),
    IncidentPattern("execa", r"(^|[^[:alnum:]_-])execa([^[:alnum:]_-]|$)", r"(?<![\w-])execa(?![\w-])"),
    IncidentPattern("commander", r"(^|[^[:alnum:]_-])commander([^[:alnum:]_-]|$)", r"(?<![\w-])commander(?![\w-])"),
    IncidentPattern("curl | sh", r"curl[^|]*\|[[:space:]]*sh", r"curl[^|]*\|\s*sh\b"),
    IncidentPattern("curl | bash", r"curl[^|]*\|[[:space:]]*bash", r"curl[^|]*\|\s*bash\b"),
    IncidentPattern("wget | sh", r"wget[^|]*\|[[:space:]]*sh", r"wget[^|]*\|\s*sh\b"),
    IncidentPattern("wget | bash", r"wget[^|]*\|[[:space:]]*bash", r"wget[^|]*\|\s*bash\b"),
    IncidentPattern("curl", r"(^|[^[:alnum:]_-])curl([^[:alnum:]_-]|$)", r"(?<![\w-])curl(?![\w-])"),
    IncidentPattern("wget", r"(^|[^[:alnum:]_-])wget([^[:alnum:]_-]|$)", r"(?<![\w-])wget(?![\w-])"),
    IncidentPattern("git clone", r"git[[:space:]]+clone", r"git\s+clone"),
    IncidentPattern("git+https", r"git\+https", r"git\+https"),
    IncidentPattern("python -c", r"python([0-9.]+)?[[:space:]]+-c", r"python(?:[0-9.]+)?\s+-c"),
    IncidentPattern("perl -e", r"perl[[:space:]]+-e", r"perl\s+-e"),
    IncidentPattern("ruby -e", r"ruby[[:space:]]+-e", r"ruby\s+-e"),
    IncidentPattern("bash -c", r"bash[[:space:]]+-c", r"bash\s+-c"),
    IncidentPattern("sh -c", r"(^|[^[:alnum:]_-])sh[[:space:]]+-c", r"(?<![\w-])sh\s+-c"),
    IncidentPattern("eval", r"(^|[^[:alnum:]_-])eval([^[:alnum:]_-]|$)", r"(?<![\w-])eval(?![\w-])"),
    IncidentPattern("base64", r"(^|[^[:alnum:]_-])base64([^[:alnum:]_-]|$)", r"(?<![\w-])base64(?![\w-])"),
    IncidentPattern("chmod +x", r"chmod[[:space:]]+\+x", r"chmod\s+\+x"),
    IncidentPattern("sudo", r"(^|[^[:alnum:]_-])sudo([^[:alnum:]_-]|$)", r"(?<![\w-])sudo(?![\w-])"),
    IncidentPattern("doas", r"(^|[^[:alnum:]_-])doas([^[:alnum:]_-]|$)", r"(?<![\w-])doas(?![\w-])"),
    IncidentPattern("su ", r"(^|[^[:alnum:]_-])su[[:space:]]+", r"(?<![\w-])su\s+"),
    IncidentPattern("rm -rf", r"rm[[:space:]]+-rf", r"rm\s+-rf"),
    IncidentPattern("chmod -R", r"chmod[[:space:]]+-R", r"chmod\s+-R"),
    IncidentPattern("chown -R", r"chown[[:space:]]+-R", r"chown\s+-R"),
    IncidentPattern("systemctl", r"(^|[^[:alnum:]_-])systemctl([^[:alnum:]_-]|$)", r"(?<![\w-])systemctl(?![\w-])"),
    IncidentPattern("pacman -S", r"pacman[[:space:]]+-S", r"pacman\s+-S"),
    IncidentPattern(".install", r"\.install", r"\.install"),
    IncidentPattern("install=", r"(^|[[:space:]])install=", r"(^|\s)install="),
    IncidentPattern("pre_install", r"pre_install", r"pre_install"),
    IncidentPattern("post_install", r"post_install", r"post_install"),
    IncidentPattern("pre_upgrade", r"pre_upgrade", r"pre_upgrade"),
    IncidentPattern("post_upgrade", r"post_upgrade", r"post_upgrade"),
    IncidentPattern("SKIP", r"SKIP", r"SKIP"),
    IncidentPattern("setcap", r"(^|[^[:alnum:]_-])setcap([^[:alnum:]_-]|$)", r"(?<![\w-])setcap(?![\w-])"),
    IncidentPattern("polkit", r"polkit", r"polkit"),
    IncidentPattern("sudoers", r"sudoers", r"sudoers"),
    IncidentPattern("udev", r"udev", r"udev"),
    IncidentPattern("dkms", r"dkms", r"dkms"),
    IncidentPattern("authorized_keys", r"authorized_keys", r"authorized_keys"),
    IncidentPattern("/etc/passwd", r"/etc/passwd", r"/etc/passwd"),
    IncidentPattern("/etc/shadow", r"/etc/shadow", r"/etc/shadow"),
)

SENSITIVE_REPOSITORY_FILE_GLOBS = (
    "*.install",
    "*.service",
    "*.timer",
    "*.socket",
    "*.rules",
    "*.policy",
    "*.hook",
)

SENSITIVE_REPOSITORY_PATH_PARTS = (
    "sudoers",
    "polkit",
    "udev",
)

SENSITIVE_PACKAGE_PATHS = (
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/usr/share/polkit-1",
    "/etc/polkit-1",
    "/usr/lib/polkit-1",
    "/usr/lib/systemd",
    "/etc/systemd",
    "/usr/lib/udev",
    "/etc/udev",
    "/usr/lib/modules",
    "/etc/profile.d",
    "/etc/cron",
    "/var/spool/cron",
    "/usr/share/dbus-1/system-services",
    "/usr/share/dbus-1/services",
)


class AurAuditRunner(QObject):
    logMessage = Signal(str)
    resultUpdated = Signal(object)
    finished = Signal(object)

    def __init__(
        self,
        package_name: str = "",
        package_info: dict[str, Any] | None = None,
        language: str | None = None,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._initial_package_name = package_name
        self._initial_package_info = dict(package_info or {})
        self._language = normalize_language(language or current_language())
        self._result = AurAuditResult()
        self._current_process: QProcess | None = None
        self._cancelled = False
        self._package_info_outputs: dict[str, str] = {}
        self._package_list_outputs: dict[str, str] = {}

    @Slot()
    def run(self) -> None:
        self.startAudit(self._initial_package_name)

    @Slot(str)
    def startAudit(self, packageName: str) -> None:
        self._cancelled = False
        self._package_info_outputs = {}
        self._package_list_outputs = {}
        self._result = AurAuditResult(
            packageName=packageName.strip(),
            packageInfo=dict(self._initial_package_info),
            status=AurAuditStatus.Running,
            statusTitle=self.tr("Auditoria em andamento"),
            statusMessage=self.tr("Coletando dados do pacote AUR."),
            auditDateTime=datetime.now().astimezone().isoformat(timespec="seconds"),
        )
        self.resultUpdated.emit(self._result)
        try:
            self._append_log("# " + self.tr("Auditoria AUR") + "\n\n")
            self._append_log(
                self.tr("Pacote: {package}\n").format(package=self._result.packageName or self.tr("(vazio)"))
            )
            self._append_log(self.tr("Data/hora: {date_time}\n\n").format(date_time=self._result.auditDateTime))
            self._validate_package_name()
            self._ensure_not_root()
            self._ensure_tool("git", self.tr("git ausente. Instale git para clonar o repositório AUR."))
            self._prepare_work_directory()
            self.cloneAurRepo()
            self.collectGitFiles()
            self.collectGitHistory()
            self.collectLastDiff()
            self.collectPkgbuildSummary()
            self.scanIncidentPatterns()
            self.scanSensitiveFiles()
            if self._result.matchedPatterns or self._result.sensitiveFiles:
                self._finish_blocked(self._build_block_reason())
                return
            self._ensure_tool(
                "makepkg",
                self.tr("makepkg ausente. Instale base-devel/pacman para validar e compilar."),
            )
            self.verifySources()
            self.buildPackage()
            self.locatePackageFiles()
            self._ensure_tool("pacman", self.tr("pacman ausente. Não foi possível inspecionar o pacote final."))
            self.inspectPackageMetadata()
            if not self.checkInstallScript():
                self._finish_blocked(self._result.blockReason)
                return
            self.inspectPackageFiles()
            if not self.checkSensitivePaths():
                self._finish_blocked(self._result.blockReason)
                return
            if not self.checkSpecialPermissions():
                self._finish_blocked(self._result.blockReason)
                return
            self._finish_ok()
        except AuditCancelled:
            self._finish_operational_error(self.tr("Auditoria cancelada pelo usuário."))
        except AuditOperationalError as exc:
            self._finish_operational_error(str(exc))
        except Exception as exc:
            self._finish_operational_error(self.tr("Erro inesperado durante a auditoria: {error}").format(error=exc))

    @Slot()
    def cancel(self) -> None:
        self._cancelled = True
        process = self._current_process
        if process and process.state() != QProcess.NotRunning:
            self._append_log("\n" + self.tr("Auditoria cancelada pelo usuário. Encerrando processo em execução.") + "\n")
            process.kill()

    def cloneAurRepo(self) -> None:
        self._ensure_not_cancelled()
        url = f"https://aur.archlinux.org/{self._result.packageName}.git"
        run = self._run_command(
            self.tr("Clonando repositório AUR"),
            "git",
            ["clone", url, self._result.workDir],
            cwd=Path(self._result.workDir).parent,
            timeout_ms=5 * 60 * 1000,
        )
        self._require_success(run, self.tr("Falha ao clonar o pacote AUR. Verifique o nome do pacote ou a rede."))

    def collectGitFiles(self) -> None:
        run = self._run_command(
            self.tr("Arquivos versionados"),
            "git",
            ["ls-files"],
            cwd=Path(self._result.workDir),
            timeout_ms=60 * 1000,
        )
        self._require_success(run, self.tr("Falha ao listar arquivos versionados com git ls-files."))
        self._result.gitFiles = sorted(line.strip() for line in run.stdout.splitlines() if line.strip())
        self._append_log("\n" + self.tr("Arquivos analisados (git ls-files | sort):") + "\n")
        self._append_log("\n".join(self._result.gitFiles) + ("\n" if self._result.gitFiles else self.tr("(nenhum)") + "\n"))

    def collectGitHistory(self) -> None:
        run = self._run_command(
            self.tr("Últimos commits"),
            "git",
            [
                "log",
                "--format=commit %h | %ad | %an <%ae> | %s",
                "--date=iso",
                "--max-count=15",
            ],
            cwd=Path(self._result.workDir),
            timeout_ms=60 * 1000,
        )
        self._require_success(run, self.tr("Falha ao coletar últimos commits."))
        self._result.gitHistory = run.stdout

    def collectLastDiff(self) -> None:
        run = self._run_command(
            self.tr("Diff do último commit"),
            "git",
            ["show", "--stat", "--patch", "--find-renames", "--find-copies", "HEAD"],
            cwd=Path(self._result.workDir),
            timeout_ms=60 * 1000,
        )
        self._require_success(run, self.tr("Falha ao coletar diff do último commit."))
        self._result.lastDiff = run.stdout

    def collectPkgbuildSummary(self) -> None:
        self._ensure_not_cancelled()
        path = Path(self._result.workDir) / "PKGBUILD"
        if not path.exists():
            raise AuditOperationalError(self.tr("PKGBUILD não encontrado no repositório clonado."))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise AuditOperationalError(self.tr("Falha ao ler PKGBUILD: {error}").format(error=exc)) from exc
        summary = self._extract_pkgbuild_fields(text)
        self._result.pkgbuildSummary = summary
        self._append_log("\n== " + self.tr("Campos principais do PKGBUILD") + " ==\n")
        self._append_log(summary + "\n")

    def scanIncidentPatterns(self) -> None:
        self._ensure_not_cancelled()
        combined_regex = "|".join(f"({pattern.grep_regex})" for pattern in INCIDENT_PATTERNS)
        run = self._run_command(
            self.tr("Padrões compatíveis com incidentes documentados"),
            "git",
            ["grep", "-nE", "-I", "-e", combined_regex],
            cwd=Path(self._result.workDir),
            timeout_ms=2 * 60 * 1000,
            allowed_returncodes=(0, 1),
        )
        if run.returncode not in (0, 1):
            raise AuditOperationalError(self.tr("Falha ao executar git grep para padrões sensíveis."))
        matches: list[IncidentPatternMatch] = []
        if run.returncode == 0:
            for line in run.stdout.splitlines():
                parsed = self._parse_git_grep_line(line)
                if parsed is None:
                    continue
                file_path, line_number, text = parsed
                labels = self._labels_for_line(text)
                if not labels:
                    labels = [self.tr("padrão sensível")]
                for label in labels:
                    matches.append(IncidentPatternMatch(label, file_path, line_number, text.strip()))
        self._result.matchedPatterns = matches
        self._append_log("\n== " + self.tr("Padrões encontrados") + " ==\n")
        if matches:
            self._append_log("\n".join(match.display() for match in matches) + "\n")
        else:
            self._append_log(
                self.tr("Nenhum padrão compatível com incidentes AUR documentados foi encontrado.") + "\n"
            )

    def scanSensitiveFiles(self) -> None:
        self._ensure_not_cancelled()
        sensitive: list[str] = []
        for file_path in self._result.gitFiles:
            name = Path(file_path).name
            lower_path = file_path.lower()
            for glob in SENSITIVE_REPOSITORY_FILE_GLOBS:
                if fnmatch.fnmatchcase(name, glob):
                    sensitive.append(self.tr("{file} (arquivo sensível: {glob})").format(file=file_path, glob=glob))
                    break
            for part in SENSITIVE_REPOSITORY_PATH_PARTS:
                if part in lower_path:
                    sensitive.append(self.tr("{file} (caminho contém {part})").format(file=file_path, part=part))
                    break
        self._result.sensitiveFiles = sorted(set(sensitive))
        self._append_log("\n== " + self.tr("Arquivos sensíveis no repositório") + " ==\n")
        if self._result.sensitiveFiles:
            self._append_log("\n".join(self._result.sensitiveFiles) + "\n")
        else:
            self._append_log(
                self.tr("Nenhum arquivo sensível bloqueante foi encontrado nos arquivos versionados.") + "\n"
            )

    def verifySources(self) -> None:
        run = self._run_command(
            self.tr("Validação de checksum e sources"),
            "makepkg",
            ["--verifysource"],
            cwd=Path(self._result.workDir),
            timeout_ms=45 * 60 * 1000,
        )
        self._result.verifySourceOutput = run.output
        self._require_success(run, self.tr("makepkg --verifysource falhou. A auditoria não foi concluída."))

    def buildPackage(self) -> None:
        run = self._run_command(
            self.tr("Build sem instalação do pacote final"),
            "makepkg",
            ["-sr"],
            cwd=Path(self._result.workDir),
            timeout_ms=2 * 60 * 60 * 1000,
        )
        self._result.buildOutput = run.output
        self._require_success(run, self.tr("makepkg -sr falhou. Isso é erro operacional ou falha de build."))

    def locatePackageFiles(self) -> None:
        self._ensure_not_cancelled()
        work_dir = Path(self._result.workDir)
        packages = [
            path
            for path in sorted(work_dir.glob("*.pkg.tar.zst"))
            if "-debug-" not in path.name and not path.name.endswith(".sig")
        ]
        self._result.packageFiles = [str(path) for path in packages]
        self._append_log("\n== " + self.tr("Pacotes finais encontrados") + " ==\n")
        if not packages:
            self._append_log(self.tr("Nenhum arquivo *.pkg.tar.zst final foi encontrado.") + "\n")
            raise AuditOperationalError(self.tr("Pacote final não encontrado após o build."))
        self._append_log("\n".join(str(path) for path in packages) + "\n")

    def inspectPackageMetadata(self) -> None:
        outputs: list[str] = []
        for package in self._result.packageFiles:
            run = self._run_command(
                self.tr("Metadados do pacote final: {package}").format(package=Path(package).name),
                "pacman",
                ["-Qip", package],
                cwd=Path(self._result.workDir),
                timeout_ms=60 * 1000,
            )
            self._require_success(run, self.tr("pacman -Qip falhou para {package}.").format(package=package))
            self._package_info_outputs[package] = run.stdout
            outputs.append(f"### {package}\n{run.stdout}")
        self._result.pacmanInfoOutput = "\n".join(outputs)

    def inspectPackageFiles(self) -> None:
        outputs: list[str] = []
        for package in self._result.packageFiles:
            run = self._run_command(
                self.tr("Arquivos que o pacote instalaria: {package}").format(package=Path(package).name),
                "pacman",
                ["-Qlp", package],
                cwd=Path(self._result.workDir),
                timeout_ms=60 * 1000,
            )
            self._require_success(run, self.tr("pacman -Qlp falhou para {package}.").format(package=package))
            self._package_list_outputs[package] = run.stdout
            outputs.append(f"### {package}\n{run.stdout}")
        self._result.pacmanListOutput = "\n".join(outputs)

    def checkInstallScript(self) -> bool:
        checks: list[str] = []
        blocked: list[str] = []
        for package, output in self._package_info_outputs.items():
            line = next((item for item in output.splitlines() if item.lower().startswith("install script")), "")
            if re.match(r"^Install Script\s*:\s*No\s*$", line):
                checks.append(f"OK: {Path(package).name}: {line.strip()}")
            else:
                reason = self.tr("{package}: Install Script não é 'No' ({field})").format(
                    package=Path(package).name,
                    field=line.strip() or self.tr("campo ausente"),
                )
                checks.append(self.tr("BLOQUEIO: {reason}").format(reason=reason))
                blocked.append(reason)
        self._result.installScriptChecks = "\n".join(checks)
        self._append_log("\n== " + self.tr("Check de Install Script") + " ==\n")
        self._append_log((self._result.installScriptChecks or self.tr("(sem dados)")) + "\n")
        if blocked:
            self._result.blockReason = self.tr("Install Script no pacote final: {items}").format(
                items="; ".join(blocked)
            )
            return False
        return True

    def checkSensitivePaths(self) -> bool:
        matches: list[str] = []
        for package, output in self._package_list_outputs.items():
            for line in output.splitlines():
                for path in SENSITIVE_PACKAGE_PATHS:
                    if path in line:
                        matches.append(
                            self.tr("{package}: {line} (contém {path})").format(
                                package=Path(package).name,
                                line=line.strip(),
                                path=path,
                            )
                        )
        if matches:
            self._result.sensitivePathChecks = self.tr("BLOQUEIO:") + "\n" + "\n".join(matches)
            self._result.blockReason = self.tr("Caminhos sensíveis no pacote final: {items}").format(
                items="; ".join(matches)
            )
            ok = False
        else:
            self._result.sensitivePathChecks = self.tr(
                "OK: nenhum caminho sensível bloqueante foi listado pelo pacman -Qlp."
            )
            ok = True
        self._append_log("\n== " + self.tr("Check de caminhos sensíveis no pacote final") + " ==\n")
        self._append_log(self._result.sensitivePathChecks + "\n")
        return ok

    def checkSpecialPermissions(self) -> bool:
        self._ensure_not_cancelled()
        extractor = shutil.which("bsdtar") or shutil.which("tar")
        if extractor is None:
            raise AuditOperationalError(
                self.tr("bsdtar/tar ausente. Não foi possível extrair o pacote para checar permissões.")
            )
        extract_root = Path(self._result.workDir) / ".aur-sentinel-extract"
        if extract_root.exists():
            shutil.rmtree(extract_root)
        extract_root.mkdir(parents=True, exist_ok=True)

        logs: list[str] = []
        findings: list[str] = []
        for package in self._result.packageFiles:
            target = extract_root / Path(package).name.replace("/", "_")
            target.mkdir(parents=True, exist_ok=True)
            run = self._run_command(
                self.tr("Extraindo pacote para checar permissões: {package}").format(package=Path(package).name),
                extractor,
                ["-xf", package, "-C", str(target)],
                cwd=Path(self._result.workDir),
                timeout_ms=5 * 60 * 1000,
            )
            self._require_success(
                run,
                self.tr("Falha ao extrair {package} para inspeção de permissões.").format(package=package),
            )
            package_findings = self._scan_setuid_setgid(target)
            findings.extend(f"{Path(package).name}: {finding}" for finding in package_findings)
            logs.append(f"### {package}")
            if package_findings:
                logs.extend(package_findings)
            else:
                logs.append(self.tr("OK: nenhum setuid/setgid encontrado."))

            getcap = shutil.which("getcap")
            if not getcap:
                raise AuditOperationalError(
                    self.tr("getcap ausente. Não foi possível checar Linux capabilities no pacote final.")
                )
            cap_run = self._run_command(
                self.tr("Checando Linux capabilities: {package}").format(package=Path(package).name),
                getcap,
                ["-r", str(target)],
                cwd=Path(self._result.workDir),
                timeout_ms=60 * 1000,
                allowed_returncodes=(0, 1),
            )
            if cap_run.returncode not in (0, 1) or cap_run.stderr.strip():
                raise AuditOperationalError(self.tr("getcap falhou ao inspecionar {package}.").format(package=package))
            cap_output = cap_run.stdout.strip()
            if cap_output:
                logs.append("Capabilities:")
                logs.append(cap_output)
                findings.extend(f"{Path(package).name}: capability: {line}" for line in cap_output.splitlines())
            else:
                logs.append(self.tr("OK: nenhuma Linux capability encontrada por getcap."))
        self._result.specialPermissionsOutput = "\n".join(logs)
        self._append_log("\n== " + self.tr("Check de setuid/setgid/capabilities") + " ==\n")
        self._append_log(self._result.specialPermissionsOutput + "\n")
        if findings:
            self._result.blockReason = self.tr("Permissões especiais no pacote final: {items}").format(
                items="; ".join(findings)
            )
            return False
        return True

    def generateAiReport(self) -> str:
        return generate_ai_report(self._result)

    def _validate_package_name(self) -> None:
        package_name = self._result.packageName
        if not package_name:
            raise AuditOperationalError(self.tr("Informe o nome do pacote AUR."))
        if not re.fullmatch(r"[A-Za-z0-9@._+-]+", package_name):
            raise AuditOperationalError(
                self.tr("Nome de pacote inválido. Use apenas letras, números, @, ., _, + e -.")
            )

    def _ensure_not_root(self) -> None:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            raise AuditOperationalError(self.tr("ERRO: não execute Aur Sentinel como root."))

    def _prepare_work_directory(self) -> None:
        downloads = downloads_dir()
        downloads.mkdir(parents=True, exist_ok=True)
        base = downloads / f"{self._result.packageName}-aur"
        work_dir = base
        if work_dir.exists():
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            work_dir = downloads / f"{self._result.packageName}-aur-{timestamp}"
            suffix = 1
            while work_dir.exists():
                suffix += 1
                work_dir = downloads / f"{self._result.packageName}-aur-{timestamp}-{suffix}"
            self._append_log(
                self.tr(
                    "O diretório {base} já existe. Para não sobrescrever, esta auditoria usará {work_dir}.\n"
                ).format(base=base, work_dir=work_dir)
            )
        self._result.workDir = str(work_dir)
        self._append_log(self.tr("Diretório de trabalho: {work_dir}\n").format(work_dir=work_dir))

    def _ensure_tool(self, program: str, message: str) -> None:
        if shutil.which(program) is None:
            raise AuditOperationalError(message)

    def _ensure_not_cancelled(self) -> None:
        if self._cancelled:
            raise AuditCancelled

    def _run_command(
        self,
        title: str,
        program: str,
        arguments: list[str],
        cwd: Path | None = None,
        timeout_ms: int = 60 * 1000,
        allowed_returncodes: tuple[int, ...] = (0,),
    ) -> ProcessRun:
        self._ensure_not_cancelled()
        command_text = " ".join([program, *arguments])
        self._append_log(f"\n== {title} ==\n$ {command_text}\n")
        process = QProcess()
        process.setProgram(program)
        process.setArguments(arguments)
        if cwd is not None:
            process.setWorkingDirectory(str(cwd))
        process.setProcessChannelMode(QProcess.SeparateChannels)
        process.setProcessEnvironment(self._process_environment())

        stdout_chunks: list[str] = []
        stderr_chunks: list[str] = []
        holder = {
            "returncode": 127,
            "timed_out": False,
            "failed_to_start": False,
            "finished": False,
        }
        loop = QEventLoop()
        timer = QTimer()
        timer.setSingleShot(True)

        def read_stdout() -> None:
            data = bytes(process.readAllStandardOutput()).decode("utf-8", errors="replace")
            if data:
                stdout_chunks.append(data)
                self._append_log(data)

        def read_stderr() -> None:
            data = bytes(process.readAllStandardError()).decode("utf-8", errors="replace")
            if data:
                stderr_chunks.append(data)
                self._append_log(data)

        def on_finished(exit_code: int, _exit_status: QProcess.ExitStatus) -> None:
            read_stdout()
            read_stderr()
            holder["returncode"] = exit_code
            holder["finished"] = True
            timer.stop()
            loop.quit()

        def on_error(error: QProcess.ProcessError) -> None:
            if error == QProcess.FailedToStart:
                holder["failed_to_start"] = True
                stderr_chunks.append(process.errorString())
                self._append_log(process.errorString() + "\n")
                timer.stop()
                loop.quit()

        def on_timeout() -> None:
            holder["timed_out"] = True
            self._append_log(self.tr("\nTimeout em {title}; encerrando processo.\n").format(title=title))
            if process.state() != QProcess.NotRunning:
                process.kill()

        process.readyReadStandardOutput.connect(read_stdout)
        process.readyReadStandardError.connect(read_stderr)
        process.finished.connect(on_finished)
        process.errorOccurred.connect(on_error)
        timer.timeout.connect(on_timeout)

        self._current_process = process
        timer.start(timeout_ms)
        process.start()
        process.closeWriteChannel()
        if not holder["failed_to_start"] and not holder["finished"]:
            loop.exec()
        read_stdout()
        read_stderr()
        self._current_process = None
        self._ensure_not_cancelled()

        run = ProcessRun(
            int(holder["returncode"]),
            "".join(stdout_chunks),
            "".join(stderr_chunks),
            bool(holder["timed_out"]),
            bool(holder["failed_to_start"]),
        )
        if run.timed_out:
            raise AuditOperationalError(self.tr("Timeout ao executar {command}.").format(command=command_text))
        if run.failed_to_start:
            raise AuditOperationalError(
                self.tr("Falha ao iniciar {program}: {error}").format(program=program, error=run.stderr.strip())
            )
        if run.returncode not in allowed_returncodes:
            self._append_log(
                self.tr("\nComando terminou com código {returncode}.\n").format(returncode=run.returncode)
            )
        return run

    def _process_environment(self) -> QProcessEnvironment:
        env = QProcessEnvironment.systemEnvironment()
        env.insert("GIT_TERMINAL_PROMPT", "0")
        env.insert("LC_ALL", "C")
        env.insert("LANG", "C")
        env.insert("MAKEPKG_COLOR", "never")
        env.insert("PACMAN_COLOR", "never")
        return env

    def _require_success(self, run: ProcessRun, message: str) -> None:
        if run.returncode != 0:
            raise AuditOperationalError(message)

    def _extract_pkgbuild_fields(self, text: str) -> str:
        lines = text.splitlines()
        found: dict[str, str] = {}
        field_set = set(PKGBUILD_FIELDS)
        index = 0
        assignment_re = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=")
        while index < len(lines):
            line = lines[index]
            match = assignment_re.match(line)
            if not match or match.group(1) not in field_set:
                index += 1
                continue
            field = match.group(1)
            block = [line.rstrip()]
            paren_balance = line.count("(") - line.count(")")
            continuation = line.rstrip().endswith("\\")
            index += 1
            while index < len(lines) and (paren_balance > 0 or continuation):
                next_line = lines[index]
                block.append(next_line.rstrip())
                paren_balance += next_line.count("(") - next_line.count(")")
                continuation = next_line.rstrip().endswith("\\")
                index += 1
            found[field] = "\n".join(block)
        output: list[str] = []
        for field in PKGBUILD_FIELDS:
            output.append(found.get(field, f"{field}=<{self.tr('não declarado')}>"))
        return "\n".join(output)

    def _parse_git_grep_line(self, line: str) -> tuple[str, int, str] | None:
        parts = line.split(":", 2)
        if len(parts) != 3:
            return None
        file_path, line_text, text = parts
        try:
            line_number = int(line_text)
        except ValueError:
            return None
        return file_path, line_number, text

    def _labels_for_line(self, text: str) -> list[str]:
        labels: list[str] = []
        for pattern in INCIDENT_PATTERNS:
            if re.search(pattern.python_regex, text, flags=re.IGNORECASE):
                labels.append(pattern.label)
        return labels

    def _scan_setuid_setgid(self, root: Path) -> list[str]:
        findings: list[str] = []
        for current_root, dirs, files in os.walk(root, followlinks=False):
            for name in [*dirs, *files]:
                path = Path(current_root) / name
                try:
                    mode = os.lstat(path).st_mode
                except OSError:
                    continue
                rel = path.relative_to(root)
                if mode & stat.S_ISUID:
                    findings.append(f"setuid: {rel} mode={oct(stat.S_IMODE(mode))}")
                if mode & stat.S_ISGID:
                    findings.append(f"setgid: {rel} mode={oct(stat.S_IMODE(mode))}")
        return findings

    def _build_block_reason(self) -> str:
        reasons: list[str] = []
        if self._result.matchedPatterns:
            labels = sorted({match.pattern for match in self._result.matchedPatterns})
            reasons.append(self.tr("padrões encontrados: {patterns}").format(patterns=", ".join(labels)))
        if self._result.sensitiveFiles:
            reasons.append(self.tr("arquivos sensíveis: {files}").format(files=", ".join(self._result.sensitiveFiles)))
        return "; ".join(reasons) if reasons else self.tr("Padrão bloqueante encontrado.")

    def _finish_ok(self) -> None:
        self._result.status = AurAuditStatus.Ok
        self._result.statusTitle = self.tr("OK — pode instalar")
        self._result.statusMessage = (
            self.tr("Nenhum padrão compatível com incidentes AUR documentados foi encontrado.")
        )
        self._result.statusDetail = (
            self.tr(
                "Isso não é uma auditoria completa do código upstream, mas o pacote passou pelo filtro contra os vetores AUR conhecidos."
            )
        )
        self._result.aiReport = self.generateAiReport()
        self._append_log("\n== " + self.tr("Resultado: OK — pode instalar") + " ==\n")
        self.resultUpdated.emit(self._result)
        self.finished.emit(self._result)

    def _finish_blocked(self, reason: str) -> None:
        self._result.status = AurAuditStatus.Blocked
        self._result.statusTitle = self.tr("INSEGURO — revisão manual necessária")
        self._result.statusMessage = (
            self.tr("Foram encontrados padrões compatíveis com incidentes AUR documentados.")
        )
        self._result.statusDetail = reason
        self._result.blockReason = reason
        self._result.aiReport = self.generateAiReport()
        self._append_log("\n== " + self.tr("Resultado: INSEGURO — revisão manual necessária") + " ==\n")
        self._append_log(reason + "\n")
        self.resultUpdated.emit(self._result)
        self.finished.emit(self._result)

    def _finish_operational_error(self, message: str) -> None:
        self._result.status = AurAuditStatus.OperationalError
        self._result.statusTitle = self.tr("Erro na auditoria")
        self._result.statusMessage = (
            self.tr("A auditoria não foi concluída por erro operacional, dependência ausente ou falha de build.")
        )
        self._result.statusDetail = message
        self._result.operationalError = message
        self._result.aiReport = self.generateAiReport()
        self._append_log("\n== " + self.tr("Resultado: Erro na auditoria") + " ==\n")
        self._append_log(message + "\n")
        self.resultUpdated.emit(self._result)
        self.finished.emit(self._result)

    def _append_log(self, text: str) -> None:
        self._result.logText += text
        self.logMessage.emit(text)
