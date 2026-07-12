"""REST authorization proxy.

Split of responsibility:
- `/auth/*` and the static frontend shell (any non-`/api/` GET) pass through:
  they carry no entity state; live data only ever comes through the filtered
  `/api/` surface or the WebSocket proxy.
- `/api/*` is default-deny. Only the explicitly handled endpoints below are
  forwarded, and their responses are filtered to the user's policy.
"""

from __future__ import annotations

import logging

from aiohttp import web

from . import audit, commands
from .filters import redact_home_location, service_call_allowed

log = logging.getLogger(__name__)

_HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "content-encoding",
}
# For transparent passthrough we relay the body byte-for-byte, so we KEEP
# Content-Encoding (the client decodes it) and only drop framing headers.
_RAW_STRIP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
}


def _bearer(request: web.Request) -> str:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return ""


def _fwd_headers(request: web.Request) -> dict[str, str]:
    return {k: v for k, v in request.headers.items() if k.lower() not in _HOP_BY_HOP | {"host"}}


class RestProxy:
    def __init__(self, gw):
        self.gw = gw

    async def handle(self, request: web.Request) -> web.StreamResponse:
        path = request.path
        if path.startswith(commands.REST_AUTH_PREFIX):
            return await self._passthrough(request)
        if not path.startswith("/api/"):
            if request.method == "GET":
                return await self._passthrough(request)
            return self._deny(None, request, "non-API write not allowed")
        return await self._handle_api(request)

    async def _handle_api(self, request: web.Request) -> web.StreamResponse:
        if self.gw.trip.is_tripped():
            return self._deny(None, request, "gateway tripped (fail closed)", status=503)

        token = _bearer(request)
        identity = await self.gw.identity.resolve(token) if token else None
        if identity is None:
            return self._deny(None, request, "missing/invalid token", status=401)

        if identity.is_admin or identity.is_owner:
            audit.allow(identity, "rest", request.method, f"{request.path} (passthrough admin)")
            return await self._passthrough(request)

        evaluator = self.gw.evaluator_for(identity)
        if evaluator is None:
            return self._deny(identity, request, "no policy for user (fail closed)")

        path, method = request.path, request.method
        # --- explicit denials (documented; anything unlisted is denied too) ---
        if any(path.startswith(p) for p in commands.REST_EXPLICIT_DENY_PREFIXES):
            return self._deny(identity, request, "endpoint denied by gateway")

        # --- plain allows ---
        if method == "GET" and path in commands.REST_ALLOW_GET_PLAIN:
            return await self._passthrough(request)
        if method == "GET" and path == "/api/config":
            return await self._config_redacted(request, identity)
        if method == "GET" and path == "/api/states":
            return await self._states_list(request, evaluator, identity)
        if method == "GET" and path.startswith("/api/states/"):
            return await self._state_single(request, evaluator, identity)
        if method == "POST" and path.startswith("/api/services/"):
            return await self._call_service(request, evaluator, identity)

        return self._deny(identity, request, "endpoint not in gateway allowlist")

    # -- specialised handlers -------------------------------------------------

    async def _states_list(self, request, evaluator, identity) -> web.StreamResponse:
        status, headers, body = await self._fetch_json(request)
        if status == 200:
            # Fail closed if HA answers with an unexpected shape.
            body = evaluator.filter_states(body) if isinstance(body, list) else []
            audit.allow(identity, "rest", "GET", f"/api/states -> {len(body)} entities")
        return web.json_response(body, status=status, headers=_clean(headers))

    async def _state_single(self, request, evaluator, identity) -> web.StreamResponse:
        entity_id = request.path[len("/api/states/") :]
        if not evaluator.allowed_read(entity_id):
            return self._deny(identity, request, f"read not permitted for {entity_id}")
        audit.allow(identity, "rest", "GET", f"/api/states/{entity_id}")
        return await self._passthrough(request)

    async def _config_redacted(self, request, identity) -> web.StreamResponse:
        status, headers, body = await self._fetch_json(request)
        if status == 200:
            body = redact_home_location(body) if isinstance(body, dict) else {}
        audit.allow(identity, "rest", "GET", "/api/config (location redacted)")
        return web.json_response(body, status=status, headers=_clean(headers))

    async def _call_service(self, request, evaluator, identity) -> web.StreamResponse:
        if "return_response" in request.query:
            return self._deny(identity, request, "return_response not filterable (v1)")
        parts = request.path[len("/api/services/") :].split("/")
        if len(parts) != 2 or not all(parts):
            return self._deny(identity, request, "malformed service path")
        domain, service = parts
        try:
            body = await request.json()
        except Exception:
            body = {}
        if not isinstance(body, dict):
            body = {}

        def resolve(kind: str, value: str):
            if kind == "area_id":
                return self.gw.registry.entities_in_area(value)
            if kind == "device_id":
                return self.gw.registry.entities_of_device(value)
            return None

        ok, reason = service_call_allowed(
            evaluator,
            domain,
            service,
            body,
            body.get("target"),
            resolve,
        )
        if not ok:
            return self._deny(identity, request, f"{domain}.{service}: {reason}")
        audit.allow(identity, "rest", "POST", f"/api/services/{domain}/{service} ({reason})")
        # Re-issue with the body we validated; filter the returned changed-states list.
        status, headers, resp_body = await self._fetch_json(request, json_body=body)
        if status in (200, 201):
            resp_body = evaluator.filter_states(resp_body) if isinstance(resp_body, list) else []
        return web.json_response(resp_body, status=status, headers=_clean(headers))

    # -- transport ------------------------------------------------------------

    async def _passthrough(self, request: web.Request) -> web.StreamResponse:
        body = await request.read()
        url = self.gw.ha_url + request.path_qs
        # Raw session: no auto-decompress, so a brotli/gzip body is relayed as-is
        # with its Content-Encoding header and the browser decodes it.
        async with self.gw.http_raw.request(
            request.method,
            url,
            headers=_fwd_headers(request),
            data=body or None,
            allow_redirects=False,
        ) as up:
            raw = await up.read()
            headers = {k: v for k, v in up.headers.items() if k.lower() not in _RAW_STRIP}
            resp = web.StreamResponse(status=up.status, headers=headers)
            await resp.prepare(request)
            await resp.write(raw)
            await resp.write_eof()
            return resp

    async def _fetch_json(self, request: web.Request, json_body=None):
        url = self.gw.ha_url + request.path_qs
        # Ask upstream for an uncompressed body so parsing needs no codec deps.
        headers = _fwd_headers(request)
        headers["Accept-Encoding"] = "identity"
        kwargs = {"headers": headers}
        if json_body is not None:
            kwargs["json"] = json_body
        else:
            data = await request.read()
            kwargs["data"] = data or None
        async with self.gw.http.request(request.method, url, **kwargs) as up:
            headers = dict(up.headers)
            try:
                body = await up.json()
            except Exception:
                body = await up.text()
            return up.status, headers, body

    def _deny(self, identity, request, reason: str, status: int = 403) -> web.StreamResponse:
        audit.deny(identity, "rest", f"{request.method} {request.path}", reason)
        return web.json_response(
            {"error": "forbidden_by_gateway", "message": reason}, status=status
        )


def _clean(headers: dict) -> dict:
    return {k: v for k, v in headers.items() if k.lower() not in _HOP_BY_HOP | {"content-type"}}
