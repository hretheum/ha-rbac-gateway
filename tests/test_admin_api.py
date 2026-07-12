"""Admin API: admin-gated policy management with live reload."""

import aiohttp
import pytest

from ha_rbac_gateway.model import Identity

pytestmark = pytest.mark.asyncio

ADMIN = {"Authorization": "Bearer admin"}
RESTRICTED = {"Authorization": "Bearer restricted"}


def base(server):
    return f"http://{server.host}:{server.port}"


async def test_context_requires_admin(gateway):
    async with aiohttp.ClientSession() as s:
        async with s.get(base(gateway) + "/rbac-admin/api/context") as r:
            assert r.status == 403  # no token
        async with s.get(base(gateway) + "/rbac-admin/api/context", headers=RESTRICTED) as r:
            assert r.status == 403  # non-admin token
        async with s.get(base(gateway) + "/rbac-admin/api/context", headers=ADMIN) as r:
            assert r.status == 200
            ctx = await r.json()
    assert {"users", "dashboards", "areas", "domains", "entities"} <= set(ctx)
    # system-generated user filtered out; admin flagged
    names = {u["name"]: u for u in ctx["users"]}
    assert "Supervisor" not in names
    assert names["Admin"]["is_admin"] is True
    assert names["Restricted"]["is_admin"] is False
    assert {e["id"] for e in ctx["entities"]} >= {"light.kitchen", "sensor.secret"}
    assert "light" in ctx["domains"]


async def test_preflight_cors(gateway):
    async with aiohttp.ClientSession() as s:
        async with s.options(base(gateway) + "/rbac-admin/api/policies/u1",
                             headers={"Origin": "http://ha.local:8123"}) as r:
            assert r.status == 204
            assert r.headers["Access-Control-Allow-Origin"] == "http://ha.local:8123"
            assert "Authorization" in r.headers["Access-Control-Allow-Headers"]


async def test_get_policy_existing_and_empty(gateway):
    async with aiohttp.ClientSession() as s:
        async with s.get(base(gateway) + "/rbac-admin/api/policies/u1", headers=ADMIN) as r:
            p = await r.json()
        assert p["user"]["id"] == "u1"
        assert {e["id"] for e in p["entities"]} == {"light.kitchen", "sensor.temp"}
        # control implies the entity is listed as control, read as read
        acc = {e["id"]: e["access"] for e in p["entities"]}
        assert acc["light.kitchen"] == "control" and acc["sensor.temp"] == "read"

        async with s.get(base(gateway) + "/rbac-admin/api/policies/nobody", headers=ADMIN) as r:
            empty = await r.json()
        assert empty["entities"] == [] and empty["user"]["id"] == "nobody"


async def test_put_policy_updates_live(gateway):
    gw = gateway.gateway
    # baseline: u1 cannot read sensor.secret
    ev = gw.evaluator_for(Identity("u1", "Restricted", False, False))
    assert not ev.allowed_read("sensor.secret")

    new_policy = {
        "user": {"id": "u1"},
        "entities": [{"id": "sensor.secret", "access": "read"}],
        "areas": [], "domains": [],
        "dashboards": {"default": "guest-home", "allowed": ["guest-home"]},
    }
    async with aiohttp.ClientSession() as s:
        async with s.put(base(gateway) + "/rbac-admin/api/policies/u1",
                         headers=ADMIN, json=new_policy) as r:
            assert r.status == 200
            assert (await r.json())["ok"] is True

    # reloaded live: the running policy set now allows it
    ev2 = gw.evaluator_for(Identity("u1", "Restricted", False, False))
    assert ev2.allowed_read("sensor.secret")
    assert not ev2.allowed_read("light.kitchen")  # replaced, not merged


async def test_put_invalid_policy_rejected(gateway):
    bad = {"user": {"id": "u1"},
           "entities": [{"id": "notanentity", "access": "read"}],  # missing domain.object
           "areas": [], "domains": [], "dashboards": {}}
    async with aiohttp.ClientSession() as s:
        async with s.put(base(gateway) + "/rbac-admin/api/policies/u1",
                         headers=ADMIN, json=bad) as r:
            assert r.status == 400
            assert (await r.json())["error"] == "invalid_policy"


async def test_put_requires_admin(gateway):
    async with aiohttp.ClientSession() as s:
        async with s.put(base(gateway) + "/rbac-admin/api/policies/u1",
                         headers=RESTRICTED, json={"user": {"id": "u1"}}) as r:
            assert r.status == 403


async def test_delete_policy_locks_out(gateway):
    gw = gateway.gateway
    async with aiohttp.ClientSession() as s:
        async with s.delete(base(gateway) + "/rbac-admin/api/policies/u1", headers=ADMIN) as r:
            assert r.status == 200
    # no policy -> user is denied everything (evaluator_for returns None)
    assert gw.evaluator_for(Identity("u1", "Restricted", False, False)) is None
