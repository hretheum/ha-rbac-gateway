"""End-to-end: real gateway in front of the fake HA. The fake filters nothing,
so anything scoped here was scoped by the gateway."""

import aiohttp
import pytest

pytestmark = pytest.mark.asyncio

RESTRICTED = {"Authorization": "Bearer restricted"}
ADMIN = {"Authorization": "Bearer admin"}


def base(server):
    return f"http://{server.host}:{server.port}"


async def test_rest_states_filtered(gateway):
    async with aiohttp.ClientSession() as s:
        async with s.get(base(gateway) + "/api/states", headers=RESTRICTED) as r:
            assert r.status == 200
            ids = {e["entity_id"] for e in await r.json()}
    assert ids == {"light.kitchen", "sensor.temp"}
    assert "sensor.secret" not in ids


async def test_rest_single_state_allowed_and_denied(gateway):
    async with aiohttp.ClientSession() as s:
        async with s.get(base(gateway) + "/api/states/sensor.temp", headers=RESTRICTED) as r:
            assert r.status == 200
        async with s.get(base(gateway) + "/api/states/sensor.secret", headers=RESTRICTED) as r:
            assert r.status == 403


async def test_rest_template_endpoint_denied(gateway):
    async with aiohttp.ClientSession() as s:
        async with s.post(base(gateway) + "/api/template", headers=RESTRICTED,
                          json={"template": "{{ states('sensor.secret') }}"}) as r:
            assert r.status == 403
            assert (await r.json())["error"] == "forbidden_by_gateway"


async def test_rest_error_log_denied(gateway):
    async with aiohttp.ClientSession() as s:
        async with s.get(base(gateway) + "/api/error_log", headers=RESTRICTED) as r:
            assert r.status == 403


async def test_rest_service_call_allowed_target(gateway):
    async with aiohttp.ClientSession() as s:
        async with s.post(base(gateway) + "/api/services/light/turn_on", headers=RESTRICTED,
                          json={"entity_id": "light.kitchen"}) as r:
            assert r.status == 200
            # response (changed states) is itself filtered: secret must be gone
            ids = {e["entity_id"] for e in await r.json()}
    assert ids == {"light.kitchen"}


async def test_rest_service_call_forbidden_target(gateway):
    async with aiohttp.ClientSession() as s:
        async with s.post(base(gateway) + "/api/services/light/turn_on", headers=RESTRICTED,
                          json={"entity_id": "light.hidden"}) as r:
            assert r.status == 403


async def test_rest_missing_token_401(gateway):
    async with aiohttp.ClientSession() as s:
        async with s.get(base(gateway) + "/api/states") as r:
            assert r.status == 401


async def test_admin_passthrough_sees_everything(gateway):
    async with aiohttp.ClientSession() as s:
        async with s.get(base(gateway) + "/api/states", headers=ADMIN) as r:
            assert r.status == 200
            ids = {e["entity_id"] for e in await r.json()}
    assert "sensor.secret" in ids  # admin is not restricted by the gateway


async def test_healthz(gateway):
    async with aiohttp.ClientSession() as s:
        async with s.get(base(gateway) + "/healthz") as r:
            assert r.status == 200
            body = await r.json()
    assert body["status"] == "ok"


# --- WebSocket ---------------------------------------------------------------

async def _ws_auth(s, url, token):
    ws = await s.ws_connect(url)
    await ws.receive_json()  # auth_required
    await ws.send_json({"type": "auth", "access_token": token})
    reply = await ws.receive_json()
    return ws, reply


async def _result(ws, mid):
    while True:
        m = await ws.receive_json()
        if m.get("id") == mid and m.get("type") == "result":
            return m
        if m.get("id") == mid and m.get("type") == "event":
            return m


async def test_ws_auth_invalid_token(gateway):
    url = base(gateway) + "/api/websocket"
    async with aiohttp.ClientSession() as s:
        ws, reply = await _ws_auth(s, url, "bogus")
        assert reply["type"] == "auth_invalid"
        await ws.close()


async def test_ws_get_states_filtered(gateway):
    url = base(gateway) + "/api/websocket"
    async with aiohttp.ClientSession() as s:
        ws, reply = await _ws_auth(s, url, "restricted")
        assert reply["type"] == "auth_ok"
        await ws.send_json({"id": 5, "type": "get_states"})
        res = await _result(ws, 5)
        ids = {e["entity_id"] for e in res["result"]}
        assert ids == {"light.kitchen", "sensor.temp"}
        await ws.close()


async def test_ws_render_template_denied(gateway):
    url = base(gateway) + "/api/websocket"
    async with aiohttp.ClientSession() as s:
        ws, _ = await _ws_auth(s, url, "restricted")
        await ws.send_json({"id": 6, "type": "render_template",
                            "template": "{{ states('sensor.secret') }}"})
        res = await _result(ws, 6)
        assert res["type"] == "result"
        assert res["success"] is False
        assert res["error"]["code"] == "unauthorized"
        await ws.close()


async def test_ws_unknown_command_denied(gateway):
    url = base(gateway) + "/api/websocket"
    async with aiohttp.ClientSession() as s:
        ws, _ = await _ws_auth(s, url, "restricted")
        await ws.send_json({"id": 7, "type": "config/entity_registry/list"})
        res = await _result(ws, 7)
        assert res["success"] is False
        await ws.close()


async def test_ws_subscribe_entities_rewritten(gateway):
    url = base(gateway) + "/api/websocket"
    async with aiohttp.ClientSession() as s:
        ws, _ = await _ws_auth(s, url, "restricted")
        # ask for everything; gateway must narrow to allowed set
        await ws.send_json({"id": 8, "type": "subscribe_entities"})
        # first the result, then the initial 'a' event
        got = {}
        for _ in range(3):
            m = await ws.receive_json()
            if m.get("id") == 8 and m.get("type") == "event":
                got = m["event"].get("a", {})
                break
        assert set(got) == {"light.kitchen", "sensor.temp"}
        await ws.close()


async def test_ws_call_service_forbidden_denied(gateway):
    url = base(gateway) + "/api/websocket"
    async with aiohttp.ClientSession() as s:
        ws, _ = await _ws_auth(s, url, "restricted")
        await ws.send_json({"id": 9, "type": "call_service", "domain": "light",
                            "service": "turn_on", "target": {"entity_id": "light.hidden"}})
        res = await _result(ws, 9)
        assert res["success"] is False
        await ws.close()


async def test_ws_trip_blocks_everything(gateway):
    gateway.gateway.trip.trip("test trip")
    url = base(gateway) + "/api/websocket"
    async with aiohttp.ClientSession() as s:
        ws, reply = await _ws_auth(s, url, "restricted")
        assert reply["type"] == "auth_invalid"
        await ws.close()
