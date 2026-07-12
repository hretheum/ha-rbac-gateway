from ha_rbac_gateway.filters import (
    filter_compressed_entities_event,
    redact_home_location,
    resolve_service_targets,
    service_call_allowed,
)
from ha_rbac_gateway.policy import PolicyEvaluator, parse_policy


class Reg:
    def area_of(self, e):
        return None

    def entities_matching(self, domains, areas):
        return set()


def _ev(text):
    return PolicyEvaluator(parse_policy(text, "p.yaml"), Reg())


CONTROL_KITCHEN = "user: { id: a }\nallow: { entities: [ { id: light.kitchen, access: control } ] }"


def test_resolve_targets_entity_list():
    ents, unresolved = resolve_service_targets(
        "light", "turn_on", {"entity_id": ["light.a", "light.b"]}, None
    )
    assert ents == {"light.a", "light.b"}
    assert unresolved == []


def test_resolve_targets_no_target_is_unresolved():
    ents, unresolved = resolve_service_targets("homeassistant", "restart", {}, None)
    assert ents == set()
    assert unresolved == ["<no-target>"]


def test_resolve_targets_entity_all_is_unresolved():
    ents, unresolved = resolve_service_targets("light", "turn_off", {"entity_id": "all"}, None)
    assert "entity_id=all" in unresolved


def test_service_allowed_when_target_in_control():
    ev = _ev(CONTROL_KITCHEN)
    ok, _ = service_call_allowed(
        ev, "light", "turn_on", {"entity_id": "light.kitchen"}, None, lambda k, v: None
    )
    assert ok


def test_service_denied_when_target_not_in_control():
    ev = _ev(CONTROL_KITCHEN)
    ok, reason = service_call_allowed(
        ev, "light", "turn_on", {"entity_id": "light.hidden"}, None, lambda k, v: None
    )
    assert not ok
    assert "light.hidden" in reason


def test_service_denied_for_untargeted_call():
    ev = _ev(CONTROL_KITCHEN)
    ok, reason = service_call_allowed(ev, "homeassistant", "restart", {}, None, lambda k, v: None)
    assert not ok


def test_service_area_target_expands_and_enforces():
    ev = _ev(CONTROL_KITCHEN)

    def resolve(kind, value):
        # area 'kitchen' resolves to exactly the allowed entity
        return {"light.kitchen"} if (kind, value) == ("area_id", "kitchen") else set()

    ok, _ = service_call_allowed(ev, "light", "turn_on", None, {"area_id": "kitchen"}, resolve)
    assert ok

    def resolve_leaky(kind, value):
        return {"light.kitchen", "light.hidden"}

    ok2, reason = service_call_allowed(
        ev, "light", "turn_on", None, {"area_id": "kitchen"}, resolve_leaky
    )
    assert not ok2
    assert "light.hidden" in reason


def test_service_area_stale_registry_denies():
    ev = _ev(CONTROL_KITCHEN)
    # resolver returns None => registry stale/unknown => must deny
    ok, reason = service_call_allowed(
        ev, "light", "turn_on", None, {"area_id": "kitchen"}, lambda k, v: None
    )
    assert not ok


def test_compressed_event_filter_drops_forbidden():
    allowed = {"light.kitchen"}.__contains__
    event = {"a": {"light.kitchen": {"s": "on"}, "sensor.secret": {"s": "x"}}}
    pruned = filter_compressed_entities_event(event, allowed)
    assert pruned == {"a": {"light.kitchen": {"s": "on"}}}


def test_compressed_event_all_forbidden_returns_none():
    allowed = {"light.kitchen"}.__contains__
    event = {"c": {"sensor.secret": {"s": "x"}}}
    assert filter_compressed_entities_event(event, allowed) is None


def test_redact_home_location_zeroes_gps_keeps_rest():
    cfg = {
        "latitude": 52.2,
        "longitude": 21.0,
        "elevation": 110,
        "version": "2026.7.1",
        "location_name": "Home",
    }
    out = redact_home_location(cfg)
    assert out["latitude"] == 0 and out["longitude"] == 0 and out["elevation"] == 0
    assert out["version"] == "2026.7.1" and out["location_name"] == "Home"
    # original not mutated
    assert cfg["latitude"] == 52.2
