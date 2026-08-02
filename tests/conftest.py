"""A minimal fake Home Assistant (REST + WS) and a gateway wired to it.

The fake is deliberately permissive: it does NO entity filtering (a non-admin
sees everything), exactly like real HA. That is the whole point — every bit of
scoping in these tests is done by the gateway, so if the gateway regressed, the
forbidden entities would leak through and the tests would fail.
"""

from __future__ import annotations

import json

import pytest_asyncio
from aiohttp import WSMsgType, web
from aiohttp.test_utils import TestServer

from ha_rbac_gateway.appkeys import GATEWAY
from ha_rbac_gateway.cli import PathOnlyAccessLogger
from ha_rbac_gateway.config import load_config
from ha_rbac_gateway.server import build_app

TOKENS = {
    "backend": {"id": "backend-user", "name": "Backend", "is_admin": True, "is_owner": False},
    "restricted": {"id": "u1", "name": "Restricted", "is_admin": False, "is_owner": False},
    "admin": {"id": "admin1", "name": "Admin", "is_admin": True, "is_owner": True},
    # Same restriction level as "restricted", but their policy opts into
    # allow.token_creation — the two exist side by side so every token test can
    # assert the grant is what makes the difference, not the user's rank.
    "tokenuser": {"id": "u2", "name": "TokenUser", "is_admin": False, "is_owner": False},
}

# What the fake HA hands back for auth/long_lived_access_token. Fictional, and
# deliberately not JWT-shaped: the security grep must never confuse it with a
# real credential.
FAKE_MINTED_TOKEN = "test-token-minted-by-fake-ha"  # noqa: S105 - fixture, not a secret

STATES = {
    "light.kitchen": {"entity_id": "light.kitchen", "state": "off"},
    "sensor.temp": {"entity_id": "sensor.temp", "state": "21"},
    "sensor.secret": {"entity_id": "sensor.secret", "state": "hunter2"},
    "light.hidden": {"entity_id": "light.hidden", "state": "on"},
}

ENTITY_REGISTRY = [
    {"entity_id": "light.kitchen", "area_id": "kitchen", "device_id": "d1"},
    {"entity_id": "sensor.temp", "area_id": "kitchen", "device_id": "d1"},
    {"entity_id": "sensor.secret", "area_id": "vault", "device_id": "d2"},
    {"entity_id": "light.hidden", "area_id": "vault", "device_id": "d2"},
]
DEVICE_REGISTRY = [
    {"id": "d1", "area_id": "kitchen"},
    {"id": "d2", "area_id": "vault"},
]


def _identity_for(token: str):
    return TOKENS.get(token)


def _rest_token(request: web.Request) -> str:
    auth = request.headers.get("Authorization", "")
    return auth[7:] if auth.startswith("Bearer ") else ""


CONFIG = {
    "version": "2026.7.1",
    "location_name": "Test Home",
    "latitude": 52.2297,
    "longitude": 21.0122,
    "elevation": 110,
    "unit_system": {"temperature": "°C"},
}


async def _config(request):
    if _identity_for(_rest_token(request)) is None:
        return web.json_response({"message": "unauthorized"}, status=401)
    if request.query.get("_malform"):  # simulate an unexpected upstream shape
        return web.json_response(["not", "a", "dict"])
    return web.json_response(dict(CONFIG))


async def _states(request):
    if _identity_for(_rest_token(request)) is None:
        return web.json_response({"message": "unauthorized"}, status=401)
    if request.query.get("_malform"):  # simulate an unexpected upstream shape
        return web.json_response({"unexpected": "not a list"})
    return web.json_response(list(STATES.values()))


async def _state_one(request):
    if _identity_for(_rest_token(request)) is None:
        return web.json_response({"message": "unauthorized"}, status=401)
    eid = request.match_info["eid"]
    if eid not in STATES:
        return web.json_response({"message": "not found"}, status=404)
    return web.json_response(STATES[eid])


async def _service(request):
    if _identity_for(_rest_token(request)) is None:
        return web.json_response({"message": "unauthorized"}, status=401)
    if "return_response" in request.query:
        # HA changes the response shape to a dict when return_response is set;
        # the service_response can carry arbitrary data. The gateway must never
        # reach here for a restricted user.
        return web.json_response({"changed_states": [], "service_response": {"secret": "LEAKED"}})
    # HA returns the list of states that changed. Include a couple to prove the
    # gateway filters even the *response* of an allowed call.
    return web.json_response([STATES["light.kitchen"], STATES["sensor.secret"]])


async def _tts_proxy(request):
    # HA core marks this view `requires_auth = False` (tts/__init__.py), so the
    # fake serves it to anyone — a local speaker fetching it carries no token.
    return web.Response(body=b"ID3fake-tts-audio", content_type="audio/mpeg")


async def _template(request):
    # Real HA would render this; the gateway must never let it get here.
    return web.json_response("LEAKED", status=200)


async def _services_catalogue(request):
    return web.json_response({"light": {"turn_on": {}}})


async def _ws(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    await ws.send_json({"type": "auth_required", "ha_version": "2026.7.1"})
    identity = None
    async for msg in ws:
        if msg.type != WSMsgType.TEXT:
            continue
        data = json.loads(msg.data)
        mtype = data.get("type")
        if identity is None:
            if mtype == "auth":
                identity = _identity_for(data.get("access_token", ""))
                if identity is None:
                    await ws.send_json({"type": "auth_invalid"})
                    await ws.close()
                    return ws
                await ws.send_json({"type": "auth_ok", "ha_version": "2026.7.1"})
            continue
        await _ws_command(ws, data, identity)
    return ws


async def _ws_command(ws, data, identity):
    mid, mtype = data.get("id"), data.get("type")

    def ok(result):
        return {"id": mid, "type": "result", "success": True, "result": result}

    if mtype == "auth/current_user":
        await ws.send_json(ok(identity))
    elif mtype == "get_states":
        if data.get("_malform"):  # unexpected upstream shape (should fail closed)
            await ws.send_json(ok({"unexpected": "not a list"}))
            return
        # Sent as a coalesced one-element JSON array frame (HA batches messages
        # this way); exercises the gateway's array-unpacking path.
        await ws.send_str(json.dumps([ok(list(STATES.values()))]))
    elif mtype == "get_config":
        await ws.send_json(ok(dict(CONFIG)))
    elif mtype == "config/entity_registry/list":
        await ws.send_json(ok(ENTITY_REGISTRY))
    elif mtype == "config/entity_registry/list_for_display":
        await ws.send_json(ok({"entity_categories": [], "entities": ENTITY_REGISTRY}))
    elif mtype == "config/device_registry/list":
        await ws.send_json(ok(DEVICE_REGISTRY))
    elif mtype == "config/area_registry/list":
        await ws.send_json(
            ok([{"area_id": "kitchen", "name": "Kitchen"}, {"area_id": "vault", "name": "Vault"}])
        )
    elif mtype == "config/auth/list":
        await ws.send_json(
            ok(
                [
                    {
                        "id": "u1",
                        "name": "Restricted",
                        "group_ids": ["system-users"],
                        "system_generated": False,
                        "is_owner": False,
                    },
                    {
                        "id": "admin1",
                        "name": "Admin",
                        "group_ids": ["system-admin"],
                        "system_generated": False,
                        "is_owner": True,
                    },
                    {
                        "id": "sys",
                        "name": "Supervisor",
                        "group_ids": ["system-admin"],
                        "system_generated": True,
                        "is_owner": False,
                    },
                ]
            )
        )
    elif mtype == "lovelace/dashboards/list":
        await ws.send_json(
            ok(
                [
                    {"url_path": "guest-home", "title": "Guest"},
                    {"url_path": "dashboard-secret", "title": "Secret"},
                ]
            )
        )
    elif mtype == "config/floor_registry/list":
        await ws.send_json(ok([{"floor_id": "ground", "name": "Ground"}]))
    elif mtype == "subscribe_entities":
        await ws.send_json(ok(None))
        ids = data.get("entity_ids") or list(STATES)
        add = {eid: {"s": STATES[eid]["state"]} for eid in ids if eid in STATES}
        await ws.send_json({"id": mid, "type": "event", "event": {"a": add}})
    elif mtype == "call_service":
        await ws.send_json(ok({"context": {"id": "ctx"}}))
    elif mtype == "lovelace/config":
        await ws.send_json(ok({"title": data.get("url_path") or "default", "views": []}))
    elif mtype == "get_panels":
        await ws.send_json(
            ok(
                {
                    "guest-home": {
                        "component_name": "lovelace",
                        "url_path": "guest-home",
                        "title": "Guest",
                        "show_in_sidebar": True,
                    },
                    "dashboard-secret": {
                        "component_name": "lovelace",
                        "url_path": "dashboard-secret",
                        "show_in_sidebar": True,
                    },
                    "config": {"component_name": "config", "url_path": "config"},
                    "profile": {"component_name": "profile", "url_path": "profile"},
                }
            )
        )
    elif mtype == "auth/long_lived_access_token":
        # Real HA returns the token string itself (auth/__init__.py:
        # connection.send_result(msg["id"], access_token)). It is scoped to the
        # authenticated connection's user; the fake ignores client_name/lifespan.
        await ws.send_json(ok(FAKE_MINTED_TOKEN))
    elif mtype == "auth/refresh_tokens":
        if data.get("_malform"):  # unexpected upstream shape (should fail closed)
            await ws.send_json(ok({"unexpected": "not a list"}))
            return
        # Metadata only — real HA never returns token values here.
        await ws.send_json(
            ok(
                [
                    {
                        "id": "rt1",
                        "client_id": None,
                        "client_name": "existing",
                        "is_current": False,
                        "last_used_ip": "127.0.0.1",
                    }
                ]
            )
        )
    elif mtype == "render_template":
        # If the gateway ever forwards this, it leaks. Emit a fake event.
        await ws.send_json(ok(None))
        await ws.send_json({"id": mid, "type": "event", "event": {"result": "LEAKED"}})
    else:
        await ws.send_json(
            {
                "id": mid,
                "type": "result",
                "success": False,
                "error": {"code": "unknown_command", "message": "Unknown command."},
            }
        )


def make_fake_ha_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/api/config", _config)
    app.router.add_get("/api/states", _states)
    app.router.add_get("/api/states/{eid}", _state_one)
    app.router.add_get("/api/services", _services_catalogue)
    app.router.add_post("/api/services/{domain}/{service}", _service)
    app.router.add_get("/api/tts_proxy/{tail:.*}", _tts_proxy)
    app.router.add_post("/api/template", _template)
    app.router.add_get("/api/websocket", _ws)
    return app


@pytest_asyncio.fixture
async def fake_ha():
    server = TestServer(make_fake_ha_app())
    # No access log for the fake: it would be the only other writer to
    # "aiohttp.access", and the tests assert on what the gateway logs there.
    await server.start_server(access_log=None)
    yield server
    await server.close()


@pytest_asyncio.fixture
async def gateway(fake_ha, tmp_path, monkeypatch):
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    (policy_dir / "u1.yaml").write_text(
        "user: { id: u1 }\n"
        "allow:\n"
        "  entities:\n"
        "    - { id: light.kitchen, access: control }\n"
        "    - { id: sensor.temp, access: read }\n"
        "dashboards:\n"
        "  default: guest-home\n"
        "  allowed: [guest-home]\n"
    )
    # Identical grants to u1, differing ONLY in allow.token_creation, so a test
    # comparing the two isolates the new field as the single cause.
    (policy_dir / "u2.yaml").write_text(
        "user: { id: u2 }\n"
        "allow:\n"
        "  token_creation: true\n"
        "  entities:\n"
        "    - { id: light.kitchen, access: control }\n"
        "    - { id: sensor.temp, access: read }\n"
        "dashboards:\n"
        "  default: guest-home\n"
        "  allowed: [guest-home]\n"
    )
    ha_url = f"http://{fake_ha.host}:{fake_ha.port}"
    env = {
        "HA_URL": ha_url,
        "HA_TOKEN": "backend",
        "POLICY_DIR": str(policy_dir),
        "DATA_DIR": str(tmp_path / "data"),
        "REGISTRY_REFRESH_INTERVAL": "3600",
        "IDENTITY_CACHE_TTL": "0",
    }
    config = load_config(env)
    app = build_app(config)
    server = TestServer(app)
    # Same access logger the entry point installs (aiohttp drops unknown kwargs
    # in TestServer.__init__ — they only take effect via start_server), so the
    # tests exercise the logging path production actually runs.
    await server.start_server(access_log_class=PathOnlyAccessLogger)
    server.gateway = app[GATEWAY]  # type: ignore[attr-defined]
    yield server
    await server.close()
