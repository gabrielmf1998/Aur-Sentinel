from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


KNOWN_AUR_INCIDENT_PATTERNS = [
    {
        "id": "AUR_2018_CURL_PIPE_BASH",
        "year": 2018,
        "label": "Padrão 2018: execução remota direta via curl | bash",
        "severity": "CRITICAL",
        "color": "red",
        "patterns": [
            r"curl\s+.*\|\s*bash",
            r"curl\s+.*\|\s*sh",
            r"wget\s+.*\|\s*bash",
            r"wget\s+.*\|\s*sh",
            r"bash\s+<\(\s*curl",
            r"sh\s+<\(\s*wget",
        ],
        "explanation": "Padrão compatível com incidente AUR de 2018, no qual pacote órfão adotado executava payload remoto.",
        "recommendation": "Reprovar salvo justificativa extrema. Revisar manualmente e usar IA/especialista antes de instalar.",
        "reference": "https://lists.archlinux.org/pipermail/aur-general/2018-July/034151.html",
    },
    {
        "id": "AUR_2018_SYSTEMD_PERSISTENCE",
        "year": 2018,
        "label": "Padrão 2018: persistência via systemd",
        "severity": "CRITICAL",
        "color": "red",
        "patterns": [
            r"systemctl\s+enable",
            r"systemctl\s+start",
            r"systemctl\s+enable\s+--now",
            r"\.service",
            r"\.timer",
        ],
        "explanation": "Persistência via systemd foi observada em abuso real de pacote AUR.",
        "recommendation": "Verificar se há criação/habilitação automática de serviço. Não instalar sem revisão manual.",
        "reference": "https://lists.archlinux.org/pipermail/aur-general/2018-July/034152.html",
    },
    {
        "id": "AUR_2025_FAKE_BROWSER_PATCH_RAT",
        "year": 2025,
        "label": "Padrão 2025: pacote patch/fix com source externo suspeito",
        "severity": "CRITICAL",
        "color": "red",
        "patterns": [
            r"firefox.*patch",
            r"librewolf.*fix",
            r"zen.*browser.*patch",
            r"patch.*bin",
            r"fix.*bin",
            r"github\.com/.*/.*patch",
            r"github\.com/.*/.*fix",
        ],
        "explanation": "Pacotes AUR maliciosos de 2025 usaram nomes de patch/fix de browsers e source externo controlado por atacante para instalar RAT.",
        "recommendation": "Validar se o source é upstream oficial. Revisar todos os scripts e arquivos baixados. Usar IA/especialista antes de instalar.",
        "reference": "https://www.bleepingcomputer.com/news/security/arch-linux-pulls-aur-packages-that-installed-chaos-rat-malware/",
    },
    {
        "id": "AUR_2026_ATOMIC_ARCH_NPM",
        "year": 2026,
        "label": "Padrão 2026 Atomic Arch: dependência npm maliciosa",
        "severity": "CRITICAL",
        "color": "red",
        "patterns": [
            r"npm\s+install\s+.*atomic-lockfile",
            r"npm\s+i\s+.*atomic-lockfile",
            r"atomic-lockfile",
            r"lockfile-js",
            r"js-digest",
        ],
        "explanation": "Padrão associado à campanha Atomic Arch, em que dependências npm maliciosas foram instaladas a partir do fluxo AUR.",
        "recommendation": "Tratar como crítico. Revisar package.json, lockfiles, scripts lifecycle e sources. Recomenda-se usar IA/especialista antes de instalar.",
        "reference": "https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency",
    },
    {
        "id": "AUR_2026_ATOMIC_ARCH_BUN",
        "year": 2026,
        "label": "Padrão 2026 Atomic Arch: Bun instalando dependência suspeita",
        "severity": "CRITICAL",
        "color": "red",
        "patterns": [
            r"bun\s+install\s+.*js-digest",
            r"bun\s+install\s+.*lockfile-js",
            r"bunx\s+",
            r"bun\s+install",
        ],
        "explanation": "Campanhas recentes abusaram de Bun/npm para puxar payload fora do AUR.",
        "recommendation": "Revisar dependências JavaScript, lockfiles e scripts lifecycle. Recomenda-se IA/especialista antes de instalar.",
        "reference": "https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency",
    },
    {
        "id": "AUR_2026_SHELL_PROFILE_VANDALISM",
        "year": 2026,
        "label": "Padrão 2026: alteração de shell profile",
        "severity": "CRITICAL",
        "color": "red",
        "patterns": [
            r"\.bashrc",
            r"\.zshrc",
            r"\.profile",
            r"config\.fish",
            r"\.config/fish/config\.fish",
            r">>\s*.*bashrc",
            r">>\s*.*zshrc",
        ],
        "explanation": "Alteração de shell profiles foi observada em abuso real pós-instalação no AUR.",
        "recommendation": "Não permitir alteração automática de shell profile sem justificativa muito clara.",
        "reference": "https://lists.archlinux.org/archives/list/aur-general%40lists.archlinux.org/thread/7EZTJXLIAQLARQNTMEW2HBWZYE626IFJ/",
    },
]


FALLBACK_KNOWN_AUR_INCIDENTS = {
    "incidents": [
        {
            "id": "atomic_arch_2026",
            "year": 2026,
            "name": "Atomic Arch npm dependency campaign",
            "severity": "CRITICAL",
            "indicators": ["atomic-lockfile", "js-digest", "lockfile-js"],
            "behaviors": [
                "npm install in install script",
                "bun install in install script",
                "node lifecycle script executing ELF",
            ],
            "recommendation": "Revisar manualmente e usar IA/especialista antes de instalar.",
            "reference": "https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency",
        }
    ]
}


@dataclass(frozen=True)
class IncidentPatternMatch:
    incident: dict[str, Any]
    regex: str
    matched_text: str
    similarity: str


def data_file_path() -> Path:
    return Path(__file__).resolve().parents[2] / "data" / "known_aur_incidents.json"


def load_known_aur_incidents(path: Path | None = None) -> list[dict[str, Any]]:
    payload: dict[str, Any]
    try:
        payload = json.loads((path or data_file_path()).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        payload = FALLBACK_KNOWN_AUR_INCIDENTS
    incidents = payload.get("incidents", [])
    if not isinstance(incidents, list):
        return FALLBACK_KNOWN_AUR_INCIDENTS["incidents"]
    return [item for item in incidents if isinstance(item, dict) and item.get("id")]


def match_known_incident_patterns(
    *,
    line: str,
    file_kind: str,
    package_name: str,
    full_text: str,
) -> list[IncidentPatternMatch]:
    matches: list[IncidentPatternMatch] = []
    for incident in KNOWN_AUR_INCIDENT_PATTERNS:
        for regex in incident.get("patterns", []):
            match = re.search(str(regex), line, flags=re.IGNORECASE)
            if not match:
                continue
            if not _is_confirmed_incident_behavior(
                incident_id=str(incident["id"]),
                line=line,
                file_kind=file_kind,
                package_name=package_name,
                full_text=full_text,
            ):
                continue
            matches.append(
                IncidentPatternMatch(
                    incident=incident,
                    regex=str(regex),
                    matched_text=match.group(0),
                    similarity=_similarity_text(str(incident["id"]), match.group(0), file_kind),
                )
            )
    return matches


def configured_indicator_matches(line: str) -> list[dict[str, Any]]:
    normalized = line.lower()
    results: list[dict[str, Any]] = []
    for incident in load_known_aur_incidents():
        indicators = incident.get("indicators", [])
        if not isinstance(indicators, list):
            continue
        for indicator in indicators:
            value = str(indicator)
            if value and _indicator_in_line(value, normalized):
                result = dict(incident)
                result["matched_indicator"] = value
                results.append(result)
    return results


def _indicator_in_line(indicator: str, line: str) -> bool:
    value = indicator.lower()
    escaped = re.escape(value)
    if value.startswith(".") or not re.match(r"^[a-z0-9_-]+$", value):
        return bool(re.search(rf"(?<![A-Za-z0-9_]){escaped}(?![A-Za-z0-9_])", line, re.IGNORECASE))
    return bool(re.search(rf"\b{escaped}\b", line, re.IGNORECASE))


def _is_confirmed_incident_behavior(
    *,
    incident_id: str,
    line: str,
    file_kind: str,
    package_name: str,
    full_text: str,
) -> bool:
    lower_line = line.lower()
    lower_name = package_name.lower()
    lower_text = full_text.lower()
    if incident_id == "AUR_2025_FAKE_BROWSER_PATCH_RAT":
        name_hit = bool(
            re.search(r"(firefox|librewolf|zen).*(patch|fix)|(?:patch|fix).*bin", lower_name)
            or re.search(r"(firefox|librewolf|zen).*(patch|fix)|(?:patch|fix).*bin", lower_text)
        )
        behavior_hit = bool(
            re.search(r"github\.com/.*/.*(?:patch|fix)", lower_line)
            or file_kind == "INSTALL"
            or re.search(r"\b(?:curl|wget|npm|bun|npx|bunx|chmod\s+\+x|bash\s+-c|sh\s+-c)\b", lower_line)
        )
        return name_hit and behavior_hit
    if incident_id == "AUR_2018_SYSTEMD_PERSISTENCE":
        if re.search(r"\bsystemctl\s+(?:enable|start)\b", lower_line):
            return True
        return False
    if incident_id == "AUR_2026_ATOMIC_ARCH_BUN":
        if re.search(r"\b(?:js-digest|lockfile-js)\b", lower_line):
            return True
        return file_kind == "INSTALL" and bool(re.search(r"\bbun(?:x|\s+install)\b", lower_line))
    if incident_id == "AUR_2026_SHELL_PROFILE_VANDALISM":
        return file_kind == "INSTALL" or bool(re.search(r">>?\s*.*(?:bashrc|zshrc|profile|config\.fish)", lower_line))
    return True


def _similarity_text(incident_id: str, matched_text: str, file_kind: str) -> str:
    if incident_id == "AUR_2026_ATOMIC_ARCH_NPM":
        return f"Encontrado indicador npm relacionado a Atomic Arch: {matched_text}"
    if incident_id == "AUR_2026_ATOMIC_ARCH_BUN":
        return f"Encontrado Bun/indicador JavaScript relacionado a Atomic Arch: {matched_text}"
    if incident_id == "AUR_2026_SHELL_PROFILE_VANDALISM":
        return f"Encontrada alteração de shell profile em contexto {file_kind}: {matched_text}"
    if incident_id == "AUR_2018_CURL_PIPE_BASH":
        return f"Encontrada execução remota direta equivalente a curl/wget pipe shell: {matched_text}"
    if incident_id == "AUR_2018_SYSTEMD_PERSISTENCE":
        return f"Encontrada persistência systemd em contexto {file_kind}: {matched_text}"
    return f"Encontrado padrão técnico similar ao incidente documentado: {matched_text}"
