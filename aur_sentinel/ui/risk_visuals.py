from __future__ import annotations


STATUS_COLORS = {
    "green": "#16a34a",
    "orange": "#f59e0b",
    "red": "#dc2626",
    "gray": "#6b7280",
    "blue": "#2563eb",
}

INSTALL_STATUS_FALLBACK = {
    "OK_INSTALL": ("OK — PODE INSTALAR", STATUS_COLORS["green"]),
    "SUSPICIOUS_ANALYZE": ("SUSPEITO — ANALISAR", STATUS_COLORS["orange"]),
    "CRITICAL_NOT_RECOMMENDED": ("CRÍTICO — NÃO RECOMENDADO", STATUS_COLORS["red"]),
    "NOT_VERIFIED": ("NÃO VERIFICADO", STATUS_COLORS["gray"]),
}


def status_for_install_status(status: object | None) -> tuple[str, str, str]:
    if status is None:
        return (
            "NÃO VERIFICADO",
            "Execute a auditoria antes de decidir.",
            STATUS_COLORS["gray"],
        )
    code = getattr(status, "code", "")
    text = getattr(status, "text", "") or INSTALL_STATUS_FALLBACK.get(code, ("NÃO VERIFICADO", ""))[0]
    subtitle = getattr(status, "subtitle", "") or "Execute a auditoria antes de decidir."
    color_name = getattr(status, "color", "gray")
    color = STATUS_COLORS.get(color_name, STATUS_COLORS["gray"])
    return text, subtitle, color


def status_for_source_risk(risk: str) -> tuple[str, str]:
    normalized = (risk or "").lower()
    if normalized in {"green", "ok"}:
        return "OK", STATUS_COLORS["green"]
    if normalized in {"yellow", "attention", "orange", "risk"}:
        return "Analisar", STATUS_COLORS["orange"]
    if normalized in {"red", "critical"}:
        return "Crítico", STATUS_COLORS["red"]
    return "Não verificado", STATUS_COLORS["gray"]
