from __future__ import annotations

from typing import Any

from aur_sentinel.aur.rpc import AurRpcClient


class AurSearchService:
    """Small UI-facing wrapper around the AUR RPC client."""

    def __init__(self, client: AurRpcClient | None = None) -> None:
        self._client = client or AurRpcClient()

    def searchPackages(self, query: str) -> list[dict[str, Any]]:
        return [package.raw for package in self._client.search(query)]

    def fetchPackageInfo(self, packageName: str) -> dict[str, Any]:
        return dict(self._client.info(packageName).raw)

