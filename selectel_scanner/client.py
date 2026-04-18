from __future__ import annotations

import asyncio
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from .models import FloatingIPRecord


IDENTITY_URL = "https://cloud.api.selcloud.ru/identity/v3/auth/tokens"


class SelectelScannerClient:
    """Scanner-oriented Selectel OpenStack/Neutron client."""

    def __init__(
        self,
        username: str,
        password: str,
        account_id: str,
        project_name: str = "",
        project_id: str = "",
        request_timeout: float = 30.0,
        regions: tuple[str, ...] = (),
    ) -> None:
        self.username = username.strip()
        self.password = password
        self.account_id = account_id.strip()
        self.project_name = project_name.strip()
        self.project_id = project_id.strip()
        self.request_timeout = max(float(request_timeout), 5.0)
        self.regions = tuple(region.strip() for region in regions if region.strip())

        self._token: str = ""
        self._token_expires: datetime | None = None
        self._auth_lock = asyncio.Lock()
        self._neutron_urls: dict[str, str] = {}
        self._external_network_ids: dict[str, str] = {}
        self._resource_regions: dict[str, str] = {}

        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.request_timeout),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            verify=False,
            follow_redirects=True,
        )

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
            await self.authenticate()

    async def authenticate(self) -> None:
        last_error: Exception | None = None
        payloads = self._project_scope_payloads()
        if not payloads:
            raise ValueError("Selectel Scanner requires project_name or project_id for project-scoped auth")

        for payload in payloads:
            try:
                response = await self._client.post(IDENTITY_URL, json=payload)
            except Exception as exc:  # pragma: no cover - network passthrough
                last_error = exc
                continue
            if response.status_code == 401:
                last_error = httpx.HTTPStatusError(
                    "Selectel authentication failed",
                    request=response.request,
                    response=response,
                )
                continue
            response.raise_for_status()
            self._token = response.headers.get("X-Subject-Token", "").strip()
            if not self._token:
                raise ValueError("Selectel authentication returned no X-Subject-Token header")

            body = response.json()
            self._token_expires = self._parse_token_expiration(body)
            token_project = body.get("token", {}).get("project", {})
            resolved_project_id = str(token_project.get("id", "")).strip()
            if resolved_project_id:
                self.project_id = resolved_project_id
            self._apply_service_catalog(body)
            return

        raise ValueError(
            "Selectel authentication failed. Check username, password, account ID, "
            "and project scope."
        ) from last_error

    def _project_scope_payloads(self) -> list[dict[str, Any]]:
        payloads: list[dict[str, Any]] = []
        for domain_key in ("name", "id"):
            project_scope: dict[str, Any]
            if self.project_id:
                project_scope = {
                    "project": {
                        "id": self.project_id,
                        "domain": {domain_key: self.account_id},
                    }
                }
            elif self.project_name:
                project_scope = {
                    "project": {
                        "name": self.project_name,
                        "domain": {domain_key: self.account_id},
                    }
                }
            else:
                continue

            payloads.append(
                {
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
                        "scope": project_scope,
                    }
                }
            )
        return payloads

    def _parse_token_expiration(self, payload: dict[str, Any]) -> datetime | None:
        raw_value = str(payload.get("token", {}).get("expires_at", "")).strip()
        if not raw_value:
            return None
        normalized = raw_value[:-1] + "+00:00" if raw_value.endswith("Z") else raw_value
        try:
            dt = datetime.fromisoformat(normalized)
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    def _apply_service_catalog(self, payload: dict[str, Any]) -> None:
        self._neutron_urls = {}
        services = payload.get("token", {}).get("catalog", [])
        for service in services:
            if str(service.get("type", "")).strip().lower() != "network":
                continue
            for endpoint in service.get("endpoints", []):
                region = str(endpoint.get("region_id") or endpoint.get("region") or "").strip()
                if not region:
                    continue
                if self.regions and region not in self.regions:
                    continue
                if endpoint.get("interface") != "public":
                    continue
                url = str(endpoint.get("url", "")).rstrip("/")
                if url:
                    self._neutron_urls[region] = url

        missing = [region for region in self.regions if region not in self._neutron_urls]
        if missing:
            raise RuntimeError(
                "Selectel service catalog is missing public network endpoints for: "
                + ", ".join(missing)
            )

    def _auth_headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self._token:
            headers["X-Auth-Token"] = self._token
        return headers

    def available_regions(self) -> tuple[str, ...]:
        return tuple(self._neutron_urls.keys())

    async def _request(
        self,
        method: str,
        url: str,
        retry_on_unauthorized: bool = True,
        **kwargs: Any,
    ) -> httpx.Response:
        extra_headers = kwargs.pop("headers", {})
        await self.ensure_authenticated()
        response = await self._client.request(
            method,
            url,
            headers={**self._auth_headers(), **extra_headers},
            **kwargs,
        )

        if response.status_code == 401 and retry_on_unauthorized:
            self._token = ""
            self._token_expires = None
            await self.ensure_authenticated()
            response = await self._client.request(
                method,
                url,
                headers={**self._auth_headers(), **extra_headers},
                **kwargs,
            )

        response.raise_for_status()
        return response

    async def list_floating_ips(
        self,
        *,
        regions: set[str] | None = None,
    ) -> list[FloatingIPRecord]:
        await self.ensure_authenticated()
        target_regions = tuple(regions or set(self.regions or self._neutron_urls.keys()))
        records: list[FloatingIPRecord] = []
        for region in target_regions:
            records.extend(await self._list_region_floating_ips(region))
        return records

    async def _list_region_floating_ips(self, region: str) -> list[FloatingIPRecord]:
        response = await self._request("GET", f"{self._neutron_url(region)}/v2.0/floatingips")
        items = response.json().get("floatingips", [])
        records = [
            FloatingIPRecord.from_payload({**item, "region": item.get("region") or region})
            for item in items
            if isinstance(item, dict)
        ]
        for record in records:
            if record.id:
                self._resource_regions[record.id] = region
        return records

    async def get_floating_ip(self, floating_ip_id: str) -> FloatingIPRecord:
        region = await self._resolve_region(floating_ip_id)
        response = await self._request("GET", f"{self._neutron_url(region)}/v2.0/floatingips/{floating_ip_id}")
        payload = response.json().get("floatingip", {})
        if not payload:
            raise RuntimeError(f"Selectel floating IP {floating_ip_id} returned an empty payload")
        record = FloatingIPRecord.from_payload({**payload, "region": payload.get("region") or region})
        if record.id:
            self._resource_regions[record.id] = region
        return record

    async def allocate_floating_ips(
        self,
        region: str,
        quantity: int,
        *,
        poll_attempts: int = 6,
        poll_delay: float = 0.7,
    ) -> list[FloatingIPRecord]:
        await self.ensure_authenticated()
        requested_count = max(1, int(quantity))
        before_task = asyncio.create_task(self._list_region_floating_ips(region))
        tasks = [asyncio.create_task(self._create_floating_ip(region)) for _ in range(requested_count)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        discovered: dict[str, FloatingIPRecord] = {}
        first_error: Exception | None = None
        for result in results:
            if isinstance(result, Exception):
                if first_error is None:
                    first_error = result
                continue
            discovered[result.id] = result

        should_reconcile = first_error is not None or len(discovered) < requested_count
        if discovered and not should_reconcile:
            if before_task.done():
                with suppress(asyncio.CancelledError, Exception):
                    before_task.result()
            else:
                before_task.cancel()
                with suppress(asyncio.CancelledError, Exception):
                    await before_task
            return list(discovered.values())

        before_ids = {record.id for record in await before_task}
        attempts = max(1, int(poll_attempts))
        if should_reconcile and first_error is not None:
            attempts = max(attempts, 12)

        for _ in range(attempts):
            await asyncio.sleep(max(0.1, float(poll_delay)))
            current_records = await self._list_region_floating_ips(region)
            for record in current_records:
                if record.id not in before_ids:
                    discovered.setdefault(record.id, record)
            if len(discovered) >= requested_count:
                break
        if discovered:
            return list(discovered.values())
        if first_error is not None:
            raise first_error
        return list(discovered.values())

    async def _create_floating_ip(self, region: str) -> FloatingIPRecord:
        network_id = await self._get_external_network_id(region)
        response = await self._request(
            "POST",
            f"{self._neutron_url(region)}/v2.0/floatingips",
            json={"floatingip": {"floating_network_id": network_id}},
        )
        payload = response.json().get("floatingip", {})
        if not payload:
            raise RuntimeError(f"Selectel create floating IP returned an empty payload for {region}")
        record = FloatingIPRecord.from_payload({**payload, "region": payload.get("region") or region})
        if record.id:
            self._resource_regions[record.id] = region
        return record

    async def _get_external_network_id(self, region: str) -> str:
        cached = self._external_network_ids.get(region, "").strip()
        if cached:
            return cached
        response = await self._request(
            "GET",
            f"{self._neutron_url(region)}/v2.0/networks",
            params={"router:external": True, "status": "ACTIVE"},
        )
        networks = response.json().get("networks", [])
        if not networks:
            raise RuntimeError(f"Selectel region {region} has no active external networks")
        network_id = str(networks[0].get("id", "")).strip()
        if not network_id:
            raise RuntimeError(f"Selectel region {region} returned an external network without ID")
        self._external_network_ids[region] = network_id
        return network_id

    async def delete_floating_ip(self, floating_ip_id: str) -> bool:
        try:
            region = await self._resolve_region(floating_ip_id)
        except KeyError:
            return True
        try:
            await self._request("DELETE", f"{self._neutron_url(region)}/v2.0/floatingips/{floating_ip_id}")
            self._resource_regions.pop(floating_ip_id, None)
            return True
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                self._resource_regions.pop(floating_ip_id, None)
                return True
            raise

    async def _resolve_region(self, floating_ip_id: str) -> str:
        known = self._resource_regions.get(floating_ip_id)
        candidates = list(self.regions or self._neutron_urls.keys())
        if known and known in candidates:
            candidates = [known] + [region for region in candidates if region != known]
        for region in candidates:
            try:
                await self._request(
                    "GET",
                    f"{self._neutron_url(region)}/v2.0/floatingips/{floating_ip_id}",
                )
                self._resource_regions[floating_ip_id] = region
                return region
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 404:
                    continue
                raise
        raise KeyError(floating_ip_id)

    def _neutron_url(self, region: str) -> str:
        url = self._neutron_urls.get(region, "").strip()
        if not url:
            raise RuntimeError(f"Selectel region {region} has no Neutron endpoint in the service catalog")
        return url

    @staticmethod
    def _extract_floating_ips(payload: dict[str, Any]) -> list[FloatingIPRecord]:
        records: dict[str, FloatingIPRecord] = {}
        for key in ("floatingips", "floatingip"):
            raw_value = payload.get(key)
            if isinstance(raw_value, list):
                for item in raw_value:
                    if isinstance(item, dict):
                        record = FloatingIPRecord.from_payload(item)
                        SelectelScannerClient._remember_record(records, record)
            elif isinstance(raw_value, dict):
                record = FloatingIPRecord.from_payload(raw_value)
                SelectelScannerClient._remember_record(records, record)
        return list(records.values())

    @staticmethod
    def _remember_record(records: dict[str, FloatingIPRecord], record: FloatingIPRecord) -> None:
        if not record.id and not record.address:
            return
        key = record.id or record.address
        records[key] = record

    async def close(self) -> None:
        await self._client.aclose()
