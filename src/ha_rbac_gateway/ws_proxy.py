"""WebSocket authorization proxy.

The gateway terminates the client WebSocket, authenticates the user's token with
HA (delegated), then opens an upstream WebSocket to HA authenticated as that same
user. Client->HA frames pass through a per-command allowlist; HA->client frames
are filtered according to what the client was allowed to subscribe to.

Fail-closed rules:
- unknown command types are answered with an error and never forwarded;
- subscribe_entities is rewritten to the user's allowed entity set (and the
  incoming stream is filtered again as defence in depth);
- subscribe_events is limited to state_changed (per-entity filtered) plus a few
  stateless UI-refresh events;
- call_service is allowed only when every resolved target entity is in the
  user's control set.
"""

from __future__ import annotations

import asyncio
import json
import logging

import aiohttp
from aiohttp import web

from . import audit, commands
from .appkeys import GATEWAY
from .filters import (
    filter_by_key,
    filter_compressed_entities_event,
    filter_entity_registry,
    filter_entity_registry_display,
    filter_panels,
    redact_home_location,
    service_call_allowed,
    state_changed_allowed,
)
from .model import Identity
from .policy import PolicyEvaluator

log = logging.getLogger(__name__)


def _err(mid, code: str, message: str) -> dict:
    return {
        "id": mid,
        "type": "result",
        "success": False,
        "error": {"code": code, "message": message},
    }


class _Sub:
    __slots__ = ("kind",)

    def __init__(self, kind: str):
        self.kind = kind  # "entities" | "state_changed" | "passthrough_event"


async def handle_ws(request: web.Request) -> web.WebSocketResponse:
    gw = request.app[GATEWAY]
    # Cap frame size on the (pre-auth) client socket so an unauthenticated peer
    # can't make the server buffer an arbitrarily large frame. HA WS commands are
    # tiny; 16 MiB is far above anything legitimate.
    client = web.WebSocketResponse(heartbeat=30, max_msg_size=16 * 1024 * 1024)
    await client.prepare(request)

    # --- delegated auth handshake ---
    await client.send_json({"type": "auth_required", "ha_version": gw.ha_version or "unknown"})
    token = await _read_client_auth(client)
    if token is None:
        await client.send_json({"type": "auth_invalid", "message": "auth handshake failed"})
        await client.close()
        return client

    if gw.trip.is_tripped():
        audit.deny(None, "ws", "auth", "gateway tripped (fail closed)")
        await client.send_json({"type": "auth_invalid", "message": "gateway unavailable"})
        await client.close()
        return client

    identity = await gw.identity.resolve(token)
    if identity is None:
        await client.send_json({"type": "auth_invalid", "message": "invalid token"})
        await client.close()
        return client

    evaluator = gw.evaluator_for(identity)
    passthrough = identity.is_admin or identity.is_owner
    if evaluator is None and not passthrough:
        audit.deny(identity, "ws", "auth", "no policy for user (fail closed)")
        await client.send_json(
            {"type": "auth_invalid", "message": "no gateway policy assigned to this user"}
        )
        await client.close()
        return client

    # --- upstream, authenticated as the same user ---
    session = aiohttp.ClientSession()
    try:
        upstream = await session.ws_connect(gw.ha_ws_url, heartbeat=30, max_msg_size=0)
    except Exception as exc:
        log.warning("upstream ws connect failed: %s", exc)
        await session.close()
        await client.send_json({"type": "auth_invalid", "message": "upstream unavailable"})
        await client.close()
        return client

    try:
        if not await _auth_upstream(upstream, token):
            await client.send_json({"type": "auth_invalid", "message": "upstream rejected token"})
            return client
        await client.send_json({"type": "auth_ok", "ha_version": gw.ha_version or "unknown"})
        audit.allow(identity, "ws", "auth", f"passthrough={passthrough}")

        conn = _Connection(gw, identity, evaluator, passthrough, client, upstream)
        gw.register_ws(conn)
        try:
            await conn.run()
        finally:
            gw.unregister_ws(conn)
    finally:
        await upstream.close()
        await session.close()
        if not client.closed:
            await client.close()
    return client


async def _read_client_auth(client: web.WebSocketResponse) -> str | None:
    try:
        async for msg in client:
            if msg.type != aiohttp.WSMsgType.TEXT:
                continue
            data = json.loads(msg.data)
            if data.get("type") == "auth" and isinstance(data.get("access_token"), str):
                return data["access_token"]
            return None
    except Exception as exc:
        log.debug("client auth read error: %s", exc)
    return None


async def _auth_upstream(upstream: aiohttp.ClientWebSocketResponse, token: str) -> bool:
    msg = await upstream.receive_json()
    if msg.get("type") != "auth_required":
        return False
    await upstream.send_json({"type": "auth", "access_token": token})
    msg = await upstream.receive_json()
    return msg.get("type") == "auth_ok"


class _Connection:
    def __init__(
        self,
        gw,
        identity: Identity,
        evaluator: PolicyEvaluator | None,
        passthrough: bool,
        client: web.WebSocketResponse,
        upstream: aiohttp.ClientWebSocketResponse,
    ):
        self.gw = gw
        self.identity = identity
        self.ev = evaluator
        self.passthrough = passthrough
        self.client = client
        self.upstream = upstream
        self.pending: dict[int, str] = {}  # request id -> result transform kind
        self.subs: dict[int, _Sub] = {}  # subscription id -> _Sub

    async def close_now(self) -> None:
        """Force this session shut (used for live policy revoke). Safe to call
        from another task; the pumps end when the sockets close."""
        for sock in (self.client, self.upstream):
            try:
                if not sock.closed:
                    await sock.close()
            except Exception as exc:  # best-effort; the session is going away
                log.debug("close_now: %r", exc)

    async def run(self) -> None:
        results = await asyncio.gather(
            self._pump_client_to_ha(),
            self._pump_ha_to_client(),
            return_exceptions=True,
        )
        for r in results:
            if isinstance(r, Exception):
                log.warning("ws pump exception (%s): %r", self.identity.user_id, r, exc_info=r)

    # -- client -> HA --------------------------------------------------------

    async def _pump_client_to_ha(self) -> None:
        try:
            async for msg in self.client:
                if msg.type != aiohttp.WSMsgType.TEXT:
                    continue
                try:
                    data = json.loads(msg.data)
                except json.JSONDecodeError:
                    continue
                if self.passthrough:
                    await self.upstream.send_json(data)
                    continue
                # HA supports coalescing several messages into one JSON array frame.
                for m in data if isinstance(data, list) else [data]:
                    if isinstance(m, dict):
                        await self._route_client_msg(m)
        finally:
            await self.upstream.close()

    async def _route_client_msg(self, data: dict) -> None:
        mid = data.get("id")
        mtype = data.get("type")
        if not isinstance(mid, int) or not isinstance(mtype, str):
            return  # protocol noise; drop

        if self.gw.trip.is_tripped():
            await self._deny(mid, mtype, "gateway tripped (fail closed)")
            return

        if mtype in commands.WS_FORWARD_PLAIN:
            await self._forward(data)
        elif mtype == commands.WS_GET_STATES:
            self.pending[mid] = "filter_states"
            await self._forward(data)
        elif mtype == commands.WS_GET_CONFIG:
            self.pending[mid] = "redact_config"
            await self._forward(data)
        elif mtype == commands.WS_SUBSCRIBE_ENTITIES:
            await self._handle_subscribe_entities(mid, data)
        elif mtype == commands.WS_SUBSCRIBE_EVENTS:
            await self._handle_subscribe_events(mid, data)
        elif mtype == commands.WS_CALL_SERVICE:
            await self._handle_call_service(mid, data)
        elif mtype == commands.WS_GET_PANELS:
            self.pending[mid] = "filter_panels"
            await self._forward(data)
        elif mtype == commands.WS_LOVELACE_CONFIG:
            await self._handle_lovelace_config(mid, data)
        elif mtype == commands.WS_LOVELACE_RESOURCES:
            await self._forward(data)
        elif mtype == commands.WS_REG_ENTITY_LIST:
            self.pending[mid] = "filter_entity_reg"
            await self._forward(data)
        elif mtype == commands.WS_REG_ENTITY_DISPLAY:
            self.pending[mid] = "filter_entity_display"
            await self._forward(data)
        elif mtype == commands.WS_REG_DEVICE_LIST:
            self.pending[mid] = "filter_device_reg"
            await self._forward(data)
        elif mtype == commands.WS_REG_AREA_LIST:
            self.pending[mid] = "filter_area_reg"
            await self._forward(data)
        elif mtype in (commands.WS_REG_FLOOR_LIST, commands.WS_REG_LABEL_LIST):
            # Floors/labels are not scoped per-entity; return an empty registry
            # rather than leak names. The frontend degrades gracefully.
            await self.client.send_json(
                {"id": mid, "type": "result", "success": True, "result": []}
            )
        elif mtype in commands.WS_SOFT_EMPTY:
            await self.client.send_json(
                {
                    "id": mid,
                    "type": "result",
                    "success": True,
                    "result": commands.WS_SOFT_EMPTY[mtype],
                }
            )
        else:
            # Includes WS_EXPLICIT_DENY and anything unknown. Default deny.
            await self._deny(mid, mtype, "command not in gateway allowlist")

    async def _handle_subscribe_entities(self, mid: int, data: dict) -> None:
        allowed = set(self.ev.enumerable_read_entities())
        requested = data.get("entity_ids")
        if isinstance(requested, list):
            target = sorted(allowed.intersection(requested))
        else:
            target = sorted(allowed)
        if not target:
            # Nothing visible: answer success and an empty initial add frame.
            self.subs[mid] = _Sub("entities")
            await self.client.send_json(
                {"id": mid, "type": "result", "success": True, "result": None}
            )
            await self.client.send_json({"id": mid, "type": "event", "event": {"a": {}}})
            audit.allow(self.identity, "ws", "subscribe_entities", "empty (nothing visible)")
            return
        self.subs[mid] = _Sub("entities")
        out = dict(data)
        out["entity_ids"] = target
        audit.allow(self.identity, "ws", "subscribe_entities", f"{len(target)} entities")
        await self.upstream.send_json(out)

    async def _handle_subscribe_events(self, mid: int, data: dict) -> None:
        event_type = data.get("event_type")
        if event_type == "state_changed":
            self.subs[mid] = _Sub("state_changed")
            audit.allow(self.identity, "ws", "subscribe_events", "state_changed (filtered)")
            await self.upstream.send_json(data)
        elif isinstance(event_type, str) and event_type in commands.WS_SAFE_EVENT_TYPES:
            self.subs[mid] = _Sub("passthrough_event")
            audit.allow(self.identity, "ws", "subscribe_events", event_type)
            await self.upstream.send_json(data)
        elif isinstance(event_type, str) and event_type in commands.WS_SYNTHETIC_EVENTS:
            # Accept so the frontend's subscription resolves, but relay nothing:
            # these registry-change events can carry ids the user may not see.
            audit.allow(self.identity, "ws", "subscribe_events", f"{event_type} (synthetic)")
            await self.client.send_json(
                {"id": mid, "type": "result", "success": True, "result": None}
            )
        else:
            await self._deny(
                mid,
                "subscribe_events",
                f"event_type {event_type!r} not allowed (use state_changed)",
            )

    async def _handle_call_service(self, mid: int, data: dict) -> None:
        if data.get("return_response"):
            await self._deny(mid, "call_service", "return_response not filterable (v1)")
            return
        domain = data.get("domain")
        service = data.get("service")
        if not isinstance(domain, str) or not isinstance(service, str):
            await self._deny(mid, "call_service", "malformed call_service")
            return
        if f"{domain}.{service}" in commands.SILENT_OK_SERVICES:
            # Acknowledge but drop — never forwarded to HA (see commands.py).
            await self.client.send_json(
                {"id": mid, "type": "result", "success": True, "result": {"context": {}}}
            )
            return

        def resolve(kind: str, value: str):
            if kind == "area_id":
                return self.gw.registry.entities_in_area(value)
            if kind == "device_id":
                return self.gw.registry.entities_of_device(value)
            return None

        ok, reason = service_call_allowed(
            self.ev,
            domain,
            service,
            data.get("service_data"),
            data.get("target"),
            resolve,
        )
        if not ok:
            await self._deny(mid, f"call_service:{domain}.{service}", reason)
            return
        audit.allow(self.identity, "ws", f"call_service:{domain}.{service}", reason)
        self.pending[mid] = "passthrough"
        await self.upstream.send_json(data)

    async def _handle_lovelace_config(self, mid: int, data: dict) -> None:
        # url_path None / "lovelace" is the router's default. If the user's real
        # default dashboard isn't the built-in overview, serve that instead (the
        # get_panels alias points here). Any other unlisted dashboard is denied —
        # the admin overview's card config would leak entity ids the user can't
        # see.
        url_path = data.get("url_path")
        dashboards = self.ev.policy.dashboards
        default = self.ev.policy.default_dashboard
        if url_path in (None, "lovelace") and "lovelace" not in dashboards and default:
            self.pending[mid] = "passthrough"
            await self.upstream.send_json({**data, "url_path": default})
        elif isinstance(url_path, str) and url_path in dashboards:
            self.pending[mid] = "passthrough"
            await self.upstream.send_json(data)
        else:
            await self._deny(mid, "lovelace/config", f"dashboard {url_path!r} not allowed")

    async def _forward(self, data: dict) -> None:
        await self.upstream.send_json(data)

    async def _deny(self, mid: int, what: str, reason: str) -> None:
        audit.deny(self.identity, "ws", what, reason)
        await self.client.send_json(_err(mid, "unauthorized", f"denied by gateway: {reason}"))

    # -- HA -> client --------------------------------------------------------

    async def _pump_ha_to_client(self) -> None:
        try:
            async for msg in self.upstream:
                if msg.type != aiohttp.WSMsgType.TEXT:
                    continue
                try:
                    data = json.loads(msg.data)
                except json.JSONDecodeError:
                    continue
                if self.passthrough:
                    await self.client.send_json(data)
                    continue
                # A frame may be a single message or a coalesced array of them.
                for m in data if isinstance(data, list) else [data]:
                    if isinstance(m, dict):
                        await self._route_ha_msg(m)
                    else:
                        await self.client.send_json(m)
        finally:
            if not self.client.closed:
                await self.client.close()

    async def _route_ha_msg(self, data: dict) -> None:
        mtype = data.get("type")
        mid = data.get("id")
        if mtype == "result" and mid in self.pending:
            kind = self.pending.pop(mid)
            data = self._transform_result(kind, data)
            await self.client.send_json(data)
        elif mtype == "event" and mid in self.subs:
            await self._relay_event(self.subs[mid], data)
        else:
            await self.client.send_json(data)

    def _transform_result(self, kind: str, data: dict) -> dict:
        if not data.get("success"):
            return data
        # Every branch must fail CLOSED if HA answers with an unexpected type:
        # an empty result, never the upstream payload passed through unfiltered.
        result = data.get("result")
        if kind == "filter_states":
            data["result"] = self.ev.filter_states(result) if isinstance(result, list) else []
        elif kind == "redact_config":
            data["result"] = redact_home_location(result) if isinstance(result, dict) else {}
        elif kind == "filter_panels":
            data["result"] = (
                filter_panels(
                    result,
                    self.ev.policy.dashboards,
                    self.ev.policy.default_dashboard,
                )
                if isinstance(result, dict)
                else {}
            )
        elif kind == "filter_entity_reg":
            data["result"] = filter_entity_registry(result, self._allowed_entities())
        elif kind == "filter_entity_display":
            data["result"] = filter_entity_registry_display(result, self._allowed_entities())
        elif kind == "filter_device_reg":
            data["result"] = filter_by_key(result, "id", self.ev.allowed_device_ids())
        elif kind == "filter_area_reg":
            data["result"] = filter_by_key(result, "area_id", self.ev.allowed_area_ids())
        return data

    def _allowed_entities(self) -> set[str]:
        return set(self.ev.enumerable_read_entities())

    async def _relay_event(self, sub: _Sub, data: dict) -> None:
        event = data.get("event")
        if not isinstance(event, dict):
            return
        allowed = self.ev.allowed_read
        if sub.kind == "entities":
            pruned = filter_compressed_entities_event(event, allowed)
            if pruned is None:
                return
            data = {**data, "event": pruned}
            await self.client.send_json(data)
        elif sub.kind == "state_changed":
            if state_changed_allowed(event, allowed):
                await self.client.send_json(data)
        else:  # passthrough_event (stateless UI refresh)
            await self.client.send_json(data)
