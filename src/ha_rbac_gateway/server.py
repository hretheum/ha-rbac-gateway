"""Gateway wiring: shared state, HTTP app, lifecycle."""

from __future__ import annotations

import logging

import aiohttp
from aiohttp import web

from .admin_api import AdminApi
from .appkeys import GATEWAY
from .canary import CanaryRunner
from .config import GatewayConfig
from .identity import IdentityResolver
from .model import Identity
from .policy import PolicyEvaluator, PolicyStore
from .registry import RegistryCache
from .rest_proxy import RestProxy
from .trip import TripSwitch
from .ws_proxy import handle_ws

log = logging.getLogger(__name__)


class Gateway:
    def __init__(self, config: GatewayConfig):
        self.config = config
        self.ha_url = config.ha_url
        self.ha_ws_url = config.ha_ws_url
        self.ha_version: str | None = None
        self.trip = TripSwitch(config.trip_file)
        self.identity = IdentityResolver(config.ha_ws_url, config.identity_cache_ttl)
        self.registry = RegistryCache(
            config.ha_ws_url, config.ha_token,
            config.registry_refresh_interval, config.registry_stale_max,
        )
        self.policies = PolicyStore.load_dir(config.policy_dir)
        self.live_ws: set = set()  # open _Connection objects, for live revoke
        self.canary = CanaryRunner(self)
        # http: decodes responses (for endpoints we parse + filter).
        # http_raw: no auto-decompress, for transparent byte-for-byte passthrough
        # (so brotli/gzip bodies are relayed with their Content-Encoding intact).
        self.http: aiohttp.ClientSession | None = None
        self.http_raw: aiohttp.ClientSession | None = None

    def evaluator_for(self, identity: Identity) -> PolicyEvaluator | None:
        policy = self.policies.find(identity)
        if policy is None:
            return None
        return PolicyEvaluator(policy, self.registry)

    def reload_policies(self) -> None:
        """Reload policies from disk, swapping the store only if the new set
        parses. A bad file therefore can't take the gateway down."""
        new = PolicyStore.load_dir(self.config.policy_dir)
        self.policies = new
        log.info("policies reloaded (%d)", len(new.all()))

    def register_ws(self, conn) -> None:
        self.live_ws.add(conn)

    def unregister_ws(self, conn) -> None:
        self.live_ws.discard(conn)

    async def disconnect_user(self, key: str) -> int:
        """Force-close a user's open WebSocket sessions so a policy change or
        revoke takes effect immediately (the frontend reconnects and picks up
        the new policy, or is denied if revoked)."""
        victims = [c for c in list(self.live_ws)
                   if key in (c.identity.user_id, c.identity.name)]
        for c in victims:
            await c.close_now()
        if victims:
            log.info("disconnected %d live ws session(s) for %s", len(victims), key)
        return len(victims)

    async def backend_ws(self, types: list[str]) -> dict:
        """Run a list of parameterless WS commands with the backend token,
        returning {type: result}. Used by the admin API for context data."""
        out: dict = {}
        async with aiohttp.ClientSession() as s, s.ws_connect(self.ha_ws_url) as ws:
            await ws.receive_json()  # auth_required
            await ws.send_json({"type": "auth", "access_token": self.config.ha_token})
            if (await ws.receive_json()).get("type") != "auth_ok":
                raise RuntimeError("backend token rejected")
            for i, mtype in enumerate(types, 1):
                await ws.send_json({"id": i, "type": mtype})
                while True:
                    m = await ws.receive_json()
                    if m.get("id") == i and m.get("type") == "result":
                        out[mtype] = m.get("result") if m.get("success") else None
                        break
        return out

    async def _fetch_version(self) -> None:
        try:
            async with self.http.get(
                f"{self.ha_url}/api/config",
                headers={"Authorization": f"Bearer {self.config.ha_token}"},
            ) as resp:
                if resp.status == 200:
                    self.ha_version = (await resp.json()).get("version")
        except Exception as exc:
            log.warning("could not fetch HA version: %s", exc)

    async def on_startup(self, app: web.Application) -> None:
        self.http = aiohttp.ClientSession()
        self.http_raw = aiohttp.ClientSession(auto_decompress=False)
        await self._fetch_version()
        await self.registry.start()
        await self.canary.start()
        log.info("gateway ready: upstream=%s ha_version=%s listen=%s:%s trip=%s",
                 self.ha_url, self.ha_version, self.config.listen_host,
                 self.config.listen_port, self.trip.path)

    async def on_cleanup(self, app: web.Application) -> None:
        await self.canary.stop()
        await self.registry.stop()
        if self.http:
            await self.http.close()
        if self.http_raw:
            await self.http_raw.close()


async def _health(request: web.Request) -> web.Response:
    gw: Gateway = request.app[GATEWAY]
    return web.json_response({
        "status": "tripped" if gw.trip.is_tripped() else "ok",
        "ha_version": gw.ha_version,
        "registry_age_s": round(gw.registry.age(), 1),
    })


def build_app(config: GatewayConfig) -> web.Application:
    gw = Gateway(config)
    rest = RestProxy(gw)
    app = web.Application()
    app[GATEWAY] = gw
    app.router.add_get("/healthz", _health)
    app.router.add_get("/api/websocket", handle_ws)
    if config.admin_api_enabled:
        AdminApi(gw).add_routes(app)  # /rbac-admin/api/* before the catch-all
    app.router.add_route("*", "/{tail:.*}", rest.handle)
    app.on_startup.append(gw.on_startup)
    app.on_cleanup.append(gw.on_cleanup)
    return app
