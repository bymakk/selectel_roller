from __future__ import annotations

"""Минимальный VPC Resell API v2 клиент Selectel.

Используется для автодискавери/создания проекта по логину/паролю/account_id.
IAM-токен со скоупом на домен (account-scoped) получается через OpenStack Keystone v3,
а затем отправляется в X-Auth-Token к `/vpc/resell/v2`.

Официальная документация: https://docs.selectel.ru/api/cloud-projects-and-resources/
"""

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx


IDENTITY_URL = "https://cloud.api.selcloud.ru/identity/v3/auth/tokens"
RESELL_BASE_URL = "https://api.selectel.ru/vpc/resell/v2"


@dataclass
class ResellProject:
    id: str
    name: str
    enabled: bool = True

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "ResellProject":
        return cls(
            id=str(payload.get("id") or "").strip(),
            name=str(payload.get("name") or "").strip(),
            enabled=bool(payload.get("enabled", True)),
        )


class SelectelResellClient:
    """Тонкий клиент Selectel VPC Resell v2 (список проектов, создание проекта).

    Аутентификация: IAM-токен со скоупом на домен (account_id).
    """

    def __init__(
        self,
        *,
        username: str,
        password: str,
        account_id: str,
        request_timeout: float = 20.0,
    ) -> None:
        self.username = (username or "").strip()
        self.password = password or ""
        self.account_id = (account_id or "").strip()
        self.request_timeout = max(float(request_timeout), 5.0)

        self._token: str = ""
        self._token_expires: datetime | None = None
        self._auth_lock = asyncio.Lock()

        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.request_timeout),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            verify=False,
            follow_redirects=True,
        )

    async def close(self) -> None:
        await self._client.aclose()

    def _token_valid(self) -> bool:
        if not self._token or not self._token_expires:
            return False
        return datetime.now(timezone.utc) < (self._token_expires - timedelta(minutes=5))

    async def ensure_authenticated(self) -> None:
        if self._token_valid():
            return
        async with self._auth_lock:
            if self._token_valid():
                return
            await self._authenticate_account_scoped()

    async def _authenticate_account_scoped(self) -> None:
        if not self.username or not self.password or not self.account_id:
            raise ValueError(
                "Для автодискавери проекта нужны username, password и account_id"
            )

        last_error: Exception | None = None
        # Selectel принимает и "name", и "id" в поле domain — пробуем оба
        for domain_key in ("name", "id"):
            payload = {
                "auth": {
                    "identity": {
                        "methods": ["password"],
                        "password": {
                            "user": {
                                "name": self.username,
                                "password": self.password,
                                "domain": {domain_key: self.account_id},
                            }
                        },
                    },
                    "scope": {"domain": {domain_key: self.account_id}},
                }
            }
            try:
                response = await self._client.post(IDENTITY_URL, json=payload)
            except Exception as exc:  # pragma: no cover - проброс сетевой ошибки
                last_error = exc
                continue
            if response.status_code in (400, 401, 403):
                last_error = httpx.HTTPStatusError(
                    "Selectel IAM authentication failed",
                    request=response.request,
                    response=response,
                )
                continue
            response.raise_for_status()
            token = response.headers.get("X-Subject-Token", "").strip()
            if not token:
                raise ValueError("Selectel IAM authentication returned no X-Subject-Token header")
            self._token = token
            self._token_expires = _parse_expiration(response.json())
            return

        raise ValueError(
            "Не удалось получить IAM-токен для аккаунта. "
            "Проверьте SEL_USERNAME / SEL_PASSWORD / SEL_ACCOUNT_ID."
        ) from last_error

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Auth-Token": self._token,
        }

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        await self.ensure_authenticated()
        url = f"{RESELL_BASE_URL.rstrip('/')}/{path.lstrip('/')}"
        response = await self._client.request(method, url, headers=self._headers(), **kwargs)
        if response.status_code == 401:
            self._token = ""
            self._token_expires = None
            await self.ensure_authenticated()
            response = await self._client.request(method, url, headers=self._headers(), **kwargs)
        response.raise_for_status()
        return response

    async def list_projects(self) -> list[ResellProject]:
        response = await self._request("GET", "/projects")
        items = response.json().get("projects", [])
        projects: list[ResellProject] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            project = ResellProject.from_payload(item)
            if project.id:
                projects.append(project)
        return projects

    async def create_project(self, name: str, *, description: str = "") -> ResellProject:
        safe_name = (name or "").strip() or "ip-roller"
        payload: dict[str, Any] = {"project": {"name": safe_name[:64]}}
        if description:
            payload["project"]["description"] = description[:255]
        response = await self._request("POST", "/projects", json=payload)
        project = response.json().get("project") or {}
        return ResellProject.from_payload(project)

    async def delete_project(self, project_id: str) -> bool:
        """Удаляет проект по id. Возвращает True, если удалён (или уже не существует).

        Selectel требует, чтобы у проекта не осталось ресурсов — поэтому вызывать
        только ПОСЛЕ удаления VM / volumes / floating IP.
        """
        pid = (project_id or "").strip()
        if not pid:
            return False
        try:
            response = await self._request("DELETE", f"/projects/{pid}")
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code if exc.response is not None else None
            if status in (404,):
                return True
            raise
        return response.status_code in (200, 202, 204)


def _parse_expiration(payload: dict[str, Any]) -> datetime | None:
    raw = str(payload.get("token", {}).get("expires_at", "")).strip()
    if not raw:
        return None
    normalized = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
