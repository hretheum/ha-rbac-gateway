"""Gateway wiring: shared state, HTTP app, lifecycle."""

from __future__ import annotations

import logging

import aiohttp
from aiohttp import web

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
        self.canary = CanaryRunner(self)
        self.http: aiohttp.ClientSession | None = None

    def evaluator_for(self, identity: Identity) -> PolicyEvaluator | None:
        policy = self.policies.find(identity)
        if policy is None:
            return None
        return PolicyEvaluator(policy, self.registry)

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
    app.router.add_route("*", "/{tail:.*}", rest.handle)
    app.on_startup.append(gw.on_startup)
    app.on_cleanup.append(gw.on_cleanup)
    return app
