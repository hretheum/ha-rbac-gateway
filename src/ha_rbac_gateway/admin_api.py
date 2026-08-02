"""Admin API for the RBAC management panel.

Everything here is gated on the caller being an HA admin/owner (their token is
resolved by HA, exactly like the proxy does it). It is the security boundary for
the management UI, so writes are validated against the real policy parser before
anything touches disk, the previous file is backed up, and a reload that fails to
parse leaves the running policy set untouched.

Served cross-origin (the panel lives in HA, the API on the gateway), so these
routes answer CORS preflight and reflect the caller's Origin. Auth is by bearer
token, not cookies, so no credentials mode is involved.
"""

from __future__ import annotations

import logging
import os
import time

import yaml
from aiohttp import web

from . import audit
from .policy import READ, PolicyError, parse_policy

log = logging.getLogger(__name__)

_ACCESS = ("read", "control")


def _cors(request: web.Request, allowed: tuple = (), extra: dict | None = None) -> dict:
    """CORS headers for the cross-origin admin panel.

    With `ADMIN_ALLOWED_ORIGINS` unset (`allowed` empty) the request Origin is
    reflected (convenient default; the API is still bearer-token gated). Set it to
    a comma-separated allowlist to only answer those origins.
    """
    origin = request.headers.get("Origin")
    headers = {
        "Access-Control-Allow-Methods": "GET, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Authorization, Content-Type",
        "Vary": "Origin",
    }
    if not allowed:
        headers["Access-Control-Allow-Origin"] = origin or "*"
    elif origin in allowed:
        headers["Access-Control-Allow-Origin"] = origin
    # else: no Allow-Origin header — the browser blocks a disallowed origin.
    if extra:
        headers.update(extra)
    return headers


def editor_to_mapping(payload: dict) -> dict:
    """Turn the UI's edit structure into the YAML mapping the parser expects.

    Only trusted shaping happens here; correctness is enforced by parse_policy.
    """

    def rules(items) -> list[dict]:
        out = []
        for it in items or []:
            if not isinstance(it, dict) or "id" not in it:
                raise PolicyError("each rule needs an 'id'")
            access = it.get("access", READ)
            if access not in _ACCESS:
                raise PolicyError(f"access must be one of {_ACCESS}, got {access!r}")
            out.append({"id": it["id"], "access": access})
        return out

    user_in = payload.get("user") or {}
    user: dict = {}
    if user_in.get("id"):
        user["id"] = user_in["id"]
    elif user_in.get("name"):
        user["name"] = user_in["name"]

    allow: dict = {}
    for kind in ("entities", "areas", "domains"):
        r = rules(payload.get(kind))
        if r:
            allow[kind] = r
    # The editor always sends the full desired state, so an absent key means
    # "off" — same as every other unchecked box. Written out only when true, to
    # keep untouched policy files byte-identical to what they were before this
    # field existed. Not coerced: a non-boolean is rejected by parse_policy.
    if payload.get("token_creation"):
        allow["token_creation"] = payload["token_creation"]

    dash_in = payload.get("dashboards") or {}
    dashboards: dict = {}
    if dash_in.get("default"):
        dashboards["default"] = dash_in["default"]
    allowed = [d for d in (dash_in.get("allowed") or []) if isinstance(d, str)]
    if allowed:
        dashboards["allowed"] = allowed

    mapping = {"user": user, "allow": allow}
    if dashboards:
        mapping["dashboards"] = dashboards
    return mapping


def _safe_filename(key: str) -> str:
    slug = "".join(c if c.isalnum() or c in "-_" else "-" for c in key)[:80]
    return f"{slug or 'user'}.yaml"


class AdminApi:
    def __init__(self, gw):
        self.gw = gw

    def add_routes(self, app: web.Application) -> None:
        app.router.add_route("OPTIONS", "/rbac-admin/api/{tail:.*}", self.preflight)
        app.router.add_get("/rbac-admin/api/context", self.context)
        app.router.add_get("/rbac-admin/api/policies", self.list_policies)
        app.router.add_get("/rbac-admin/api/policies/{key}", self.get_policy)
        app.router.add_put("/rbac-admin/api/policies/{key}", self.put_policy)
        app.router.add_delete("/rbac-admin/api/policies/{key}", self.delete_policy)

    # -- helpers -------------------------------------------------------------

    async def preflight(self, request: web.Request) -> web.Response:
        return web.Response(
            status=204, headers=_cors(request, self.gw.config.admin_allowed_origins)
        )

    async def _require_admin(self, request: web.Request):
        auth = request.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else ""
        identity = await self.gw.identity.resolve(token) if token else None
        if identity is None or not (identity.is_admin or identity.is_owner):
            audit.deny(identity, "admin", request.method, f"{request.path} (not admin)")
            return None, web.json_response(
                {"error": "forbidden", "message": "admin token required"},
                status=403,
                headers=_cors(request, self.gw.config.admin_allowed_origins),
            )
        return identity, None

    def _json(self, request, data, status=200):
        return web.json_response(
            data, status=status, headers=_cors(request, self.gw.config.admin_allowed_origins)
        )

    def _existing_file_for(self, key: str) -> str:
        """Reuse the file a user's policy already lives in, else a new name."""
        for policy in self.gw.policies.all():
            if key in (policy.match_user_id, policy.match_user_name):
                return policy.source_file
        return _safe_filename(key)

    # -- handlers ------------------------------------------------------------

    async def context(self, request: web.Request) -> web.Response:
        identity, err = await self._require_admin(request)
        if err:
            return err
        res = await self.gw.backend_ws(
            [
                "config/auth/list",
                "lovelace/dashboards/list",
                "config/area_registry/list",
                "config/entity_registry/list",
                "config/device_registry/list",
            ]
        )
        users = []
        for u in res.get("config/auth/list") or []:
            if u.get("system_generated"):
                continue
            is_admin = "system-admin" in (u.get("group_ids") or [])
            users.append(
                {
                    "id": u["id"],
                    "name": u.get("name") or u["id"],
                    "is_admin": is_admin,
                    "is_owner": bool(u.get("is_owner")),
                }
            )
        dashboards = [
            {"url_path": d.get("url_path"), "title": d.get("title")}
            for d in (res.get("lovelace/dashboards/list") or [])
            if d.get("url_path")
        ]
        areas = [
            {"id": a["area_id"], "name": a.get("name") or a["area_id"]}
            for a in (res.get("config/area_registry/list") or [])
            if a.get("area_id")
        ]
        device_area = {
            d["id"]: d.get("area_id")
            for d in (res.get("config/device_registry/list") or [])
            if d.get("id")
        }
        entities = []
        domains = set()
        for e in res.get("config/entity_registry/list") or []:
            eid = e.get("entity_id")
            if not eid:
                continue
            domains.add(eid.split(".", 1)[0])
            area = e.get("area_id") or device_area.get(e.get("device_id"))
            entities.append(
                {"id": eid, "name": e.get("name") or e.get("original_name") or eid, "area_id": area}
            )
        return self._json(
            request,
            {
                "users": sorted(users, key=lambda u: u["name"].lower()),
                "dashboards": sorted(dashboards, key=lambda d: (d.get("title") or "").lower()),
                "areas": sorted(areas, key=lambda a: a["name"].lower()),
                "domains": sorted(domains),
                "entities": sorted(entities, key=lambda e: e["id"]),
            },
        )

    async def list_policies(self, request: web.Request) -> web.Response:
        identity, err = await self._require_admin(request)
        if err:
            return err
        return self._json(
            request,
            {
                "policies": [p.to_editor_dict() for p in self.gw.policies.all()],
            },
        )

    async def get_policy(self, request: web.Request) -> web.Response:
        identity, err = await self._require_admin(request)
        if err:
            return err
        key = request.match_info["key"]
        for p in self.gw.policies.all():
            if key in (p.match_user_id, p.match_user_name):
                return self._json(request, p.to_editor_dict())
        # empty template for a user with no policy yet
        return self._json(
            request,
            {
                "user": {"id": key, "name": None},
                "entities": [],
                "areas": [],
                "domains": [],
                "token_creation": False,
                "dashboards": {"default": None, "allowed": []},
            },
        )

    async def put_policy(self, request: web.Request) -> web.Response:
        identity, err = await self._require_admin(request)
        if err:
            return err
        key = request.match_info["key"]
        try:
            payload = await request.json()
        except Exception:
            return self._json(request, {"error": "bad_json"}, status=400)

        filename = self._existing_file_for(key)
        try:
            mapping = editor_to_mapping(payload)
            text = yaml.safe_dump(mapping, allow_unicode=True, sort_keys=False)
            parse_policy(text, filename)  # validate exactly as the gateway will
        except PolicyError as exc:
            return self._json(request, {"error": "invalid_policy", "message": str(exc)}, status=400)

        path = os.path.join(self.gw.config.policy_dir, filename)
        if os.path.exists(path):
            _copy(path, f"{path}.bak-{time.strftime('%Y%m%d%H%M%S')}")
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)

        try:
            self.gw.reload_policies()
        except PolicyError as exc:
            return self._json(request, {"error": "reload_failed", "message": str(exc)}, status=500)
        # Apply live: drop the user's open sessions so they reconnect under the
        # new policy (edits and revokes both take effect immediately).
        await self.gw.disconnect_user(key)
        audit.allow(identity, "admin", "PUT", f"policy {filename}")
        return self._json(request, {"ok": True, "file": filename})

    async def delete_policy(self, request: web.Request) -> web.Response:
        identity, err = await self._require_admin(request)
        if err:
            return err
        key = request.match_info["key"]
        filename = None
        for p in self.gw.policies.all():
            if key in (p.match_user_id, p.match_user_name):
                filename = p.source_file
                break
        if filename is None:
            return self._json(request, {"ok": True, "note": "no policy"})
        path = os.path.join(self.gw.config.policy_dir, filename)
        if os.path.exists(path):
            _copy(path, f"{path}.bak-{time.strftime('%Y%m%d%H%M%S')}")
            os.remove(path)
        self.gw.reload_policies()
        await self.gw.disconnect_user(key)  # cut any live session immediately
        audit.allow(identity, "admin", "DELETE", f"policy {filename}")
        return self._json(request, {"ok": True})


def _copy(src: str, dst: str) -> None:
    with open(src, "rb") as a, open(dst, "wb") as b:
        b.write(a.read())
