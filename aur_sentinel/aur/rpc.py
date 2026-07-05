from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


AUR_RPC_URL = "https://aur.archlinux.org/rpc/"
USER_AGENT = "aur-sentinel/0.1 (+https://aur.archlinux.org)"


class AurRpcError(RuntimeError):
    pass


@dataclass
class AurPackage:
    raw: dict[str, Any]

    def get(self, key: str, default: Any = None) -> Any:
        return self.raw.get(key, default)

    @property
    def name(self) -> str:
        return str(self.raw.get("Name", ""))


class AurRpcClient:
    def __init__(self, timeout: int = 15) -> None:
        self.timeout = timeout

    def search(self, query: str) -> list[AurPackage]:
        query = query.strip()
        if not query:
            return []
        payload = self._request({"v": "5", "type": "search", "by": "name-desc", "arg": query})
        return [AurPackage(item) for item in payload.get("results", [])]

    def info(self, package_name: str) -> AurPackage:
        payload = self._request([("v", "5"), ("type", "info"), ("arg[]", package_name)])
        results = payload.get("results", [])
        if not results:
            raise AurRpcError(f"Pacote nao encontrado no AUR: {package_name}")
        return AurPackage(results[0])

    def _request(self, params: dict[str, str] | list[tuple[str, str]]) -> dict[str, Any]:
        query = urllib.parse.urlencode(params)
        request = urllib.request.Request(
            AUR_RPC_URL + "?" + query,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                data = response.read()
        except urllib.error.URLError as exc:
            raise AurRpcError(f"Falha ao acessar AUR RPC: {exc}") from exc
        try:
            payload = json.loads(data.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise AurRpcError("Resposta invalida da AUR RPC") from exc
        if payload.get("type") == "error":
            raise AurRpcError(str(payload.get("error", "Erro desconhecido da AUR RPC")))
        return payload
