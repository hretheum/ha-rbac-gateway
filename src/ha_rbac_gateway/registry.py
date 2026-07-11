"""Registry snapshot: entity -> area mapping fetched from HA with the backend token.

This is the ONLY place the gateway uses its privileged backend token, and it is
read-only plumbing: area/device/entity registry lists, used to expand area rules
and to enumerate entities for subscription rewriting. User traffic is NEVER
forwarded with the backend token (see docs/architecture.md).
"""

from __future__ import annotations

import asyncio
import logging
import time

import aiohttp

log = logging.getLogger(__name__)


class RegistryError(Exception):
    pass


class RegistryCache:
    def __init__(self, ha_ws_url: str, token: str, refresh_interval: int, stale_max: int):
        self._ws_url = ha_ws_url
        self._token = token
        self._refresh_interval = refresh_interval
        self._stale_max = stale_max
        self._entity_area: dict[str, str | None] = {}
        self._entity_device: dict[str, str | None] = {}
        self._fetched_at: float = 0.0
        self._task: asyncio.Task | None = None

    # -- lifecycle -----------------------------------------------------------

    async def start(self) -> None:
        """Initial fetch (must succeed — fail closed at boot) + background refresh."""
        await self.refresh()
        self._task = asyncio.create_task(self._refresh_loop(), name="registry-refresh")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _refresh_loop(self) -> None:
        while True:
            await asyncio.sleep(self._refresh_interval)
            try:
                await self.refresh()
            except Exception as exc:  # keep serving the old snapshot, narrowing over time
                log.warning("registry refresh failed (snapshot age %.0fs): %s",
                            self.age(), exc)

    # -- fetching ------------------------------------------------------------

    async def refresh(self) -> None:
        async with aiohttp.ClientSession() as session:
            async with session.ws_connect(self._ws_url, heartbeat=25) as ws:
                msg = await ws.receive_json()
                if msg.get("type") != "auth_required":
                    raise RegistryError(f"unexpected first frame: {msg.get('type')}")
                await ws.send_json({"type": "auth", "access_token": self._token})
                msg = await ws.receive_json()
                if msg.get("type") != "auth_ok":
                    raise RegistryError(
                        "backend token rejected by HA (auth_invalid) — check HA_TOKEN")

                async def cmd(mid: int, mtype: str) -> list:
                    await ws.send_json({"id": mid, "type": mtype})
                    while True:
                        m = await ws.receive_json()
                        if m.get("id") == mid and m.get("type") == "result":
                            if not m.get("success"):
                                raise RegistryError(f"{mtype} failed: {m.get('error')}")
                            return m["result"]

                entities = await cmd(1, "config/entity_registry/list")
                devices = await cmd(2, "config/device_registry/list")

        device_area = {d["id"]: d.get("area_id") for d in devices if isinstance(d, dict)}
        mapping: dict[str, str | None] = {}
        dev_map: dict[str, str | None] = {}
        for e in entities:
            if not isinstance(e, dict) or "entity_id" not in e:
                continue
            device_id = e.get("device_id")
            area = e.get("area_id") or device_area.get(device_id or "", None)
            mapping[e["entity_id"]] = area
            dev_map[e["entity_id"]] = device_id
        self._entity_area = mapping
        self._entity_device = dev_map
        self._fetched_at = time.monotonic()
        log.info("registry snapshot: %d entities (%d with area)",
                 len(mapping), sum(1 for a in mapping.values() if a))

    # -- queries (fail closed on staleness) -----------------------------------

    def age(self) -> float:
        return time.monotonic() - self._fetched_at if self._fetched_at else float("inf")

    def _fresh(self) -> bool:
        return self.age() <= self._stale_max

    def area_of(self, entity_id: str) -> str | None:
        """Area of an entity, or None when unknown OR when the snapshot is stale.

        Returning None on staleness makes area rules deny — never guess from
        old data forever; a long-unreachable HA means we narrow to static rules.
        """
        if not self._fresh():
            return None
        return self._entity_area.get(entity_id)

    def device_of(self, entity_id: str) -> str | None:
        """Device of an entity, or None when unknown or the snapshot is stale."""
        if not self._fresh():
            return None
        return self._entity_device.get(entity_id)

    def entities_matching(self, domains: frozenset[str], areas: frozenset[str]) -> set[str]:
        out: set[str] = set()
        if not self._fresh():
            return out  # fail closed: no expansion from a stale snapshot
        for eid, area in self._entity_area.items():
            if eid.split(".", 1)[0] in domains or (area is not None and area in areas):
                out.add(eid)
        return out

    def entities_in_area(self, area_id: str) -> set[str] | None:
        """Entities in an area, or None when the snapshot is stale (=> deny)."""
        if not self._fresh():
            return None
        return {eid for eid, area in self._entity_area.items() if area == area_id}

    def entities_of_device(self, device_id: str) -> set[str] | None:
        """Entities belonging to a device, or None when stale (=> deny)."""
        if not self._fresh():
            return None
        return {eid for eid, dev in self._entity_device.items() if dev == device_id}
