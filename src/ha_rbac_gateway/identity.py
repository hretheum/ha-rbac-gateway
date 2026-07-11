"""Token -> identity resolution, delegated to Home Assistant itself.

The gateway never decodes or verifies tokens locally: it opens a short
WebSocket connection to HA, authenticates WITH THE USER'S OWN TOKEN and asks
`auth/current_user`. HA is the sole authority on token validity; the gateway
only caches the answer briefly (keyed by token digest, never the token).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time

import aiohttp

from .model import Identity

log = logging.getLogger(__name__)

_NEGATIVE_TTL = 30.0


class IdentityResolver:
    def __init__(self, ha_ws_url: str, cache_ttl: int):
        self._ws_url = ha_ws_url
        self._ttl = float(cache_ttl)
        self._cache: dict[str, tuple[float, Identity | None]] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    @staticmethod
    def _key(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    async def resolve(self, token: str) -> Identity | None:
        """Identity for a token, or None if HA rejects it. Fails closed on errors."""
        if not token:
            return None
        key = self._key(token)
        now = time.monotonic()
        hit = self._cache.get(key)
        if hit and now < hit[0]:
            return hit[1]
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            hit = self._cache.get(key)
            now = time.monotonic()
            if hit and now < hit[0]:
                return hit[1]
            try:
                identity = await self._ask_ha(token)
            except Exception as exc:
                log.warning("identity resolution failed (denying): %s", exc)
                return None  # fail closed; no caching of infrastructure errors
            ttl = self._ttl if identity else _NEGATIVE_TTL
            self._cache[key] = (now + ttl, identity)
            if len(self._cache) > 10_000:  # bound memory
                self._cache.clear()
            return identity

    async def _ask_ha(self, token: str) -> Identity | None:
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.ws_connect(self._ws_url) as ws:
                msg = await ws.receive_json()
                if msg.get("type") != "auth_required":
                    raise RuntimeError(f"unexpected first frame {msg.get('type')!r}")
                await ws.send_json({"type": "auth", "access_token": token})
                msg = await ws.receive_json()
                if msg.get("type") == "auth_invalid":
                    return None
                if msg.get("type") != "auth_ok":
                    raise RuntimeError(f"unexpected auth reply {msg.get('type')!r}")
                await ws.send_json({"id": 1, "type": "auth/current_user"})
                while True:
                    m = await ws.receive_json()
                    if m.get("id") == 1 and m.get("type") == "result":
                        if not m.get("success"):
                            raise RuntimeError(f"auth/current_user failed: {m.get('error')}")
                        r = m["result"]
                        return Identity(
                            user_id=r["id"],
                            name=r.get("name") or "",
                            is_admin=bool(r.get("is_admin")),
                            is_owner=bool(r.get("is_owner")),
                        )
