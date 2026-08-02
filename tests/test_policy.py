import pytest

from ha_rbac_gateway.model import Identity
from ha_rbac_gateway.policy import (
    PolicyError,
    PolicyEvaluator,
    PolicyStore,
    parse_policy,
)


class FakeRegistry:
    def __init__(self, area_map=None, domain_entities=None):
        self._areas = area_map or {}
        self._domain_entities = domain_entities or {}

    def area_of(self, entity_id):
        return self._areas.get(entity_id)

    def entities_matching(self, domains, areas):
        out = set()
        for eid, area in self._areas.items():
            if eid.split(".", 1)[0] in domains or area in areas:
                out.add(eid)
        out |= {e for d, ents in self._domain_entities.items() if d in domains for e in ents}
        return out


def _policy(text, fn="p.yaml"):
    return parse_policy(text, fn)


def test_parse_minimal_entity_policy():
    p = _policy(
        """
        user: { id: abc }
        allow:
          entities:
            - { id: light.kitchen, access: control }
            - { id: sensor.temp }
        """
    )
    assert p.match_user_id == "abc"
    assert p.control.entities == {"light.kitchen"}
    assert p.read.entities == {"sensor.temp"}


def test_reject_unknown_key():
    with pytest.raises(PolicyError, match="unknown key"):
        _policy("user: { id: a }\nallow: { entitites: [] }")  # typo'd key


def test_reject_both_id_and_name():
    with pytest.raises(PolicyError, match="exactly one"):
        _policy("user: { id: a, name: b }\nallow: {}")


def test_reject_no_user_match():
    with pytest.raises(PolicyError, match="exactly one"):
        _policy("user: {}\nallow: {}")


def test_reject_bad_entity_id():
    with pytest.raises(PolicyError, match="domain.object_id"):
        _policy("user: { id: a }\nallow: { entities: [ { id: notanentity } ] }")


def test_reject_bad_access_level():
    with pytest.raises(PolicyError, match="access must be"):
        _policy("user: { id: a }\nallow: { entities: [ { id: a.b, access: write } ] }")


def test_duplicate_user_id_across_files_rejected():
    p1 = _policy("user: { id: dup }\nallow: {}", "a.yaml")
    p2 = _policy("user: { id: dup }\nallow: {}", "b.yaml")
    with pytest.raises(PolicyError, match="duplicate"):
        PolicyStore([p1, p2])


def test_control_implies_read():
    p = _policy("user: { id: a }\nallow: { entities: [ { id: light.k, access: control } ] }")
    ev = PolicyEvaluator(p, FakeRegistry())
    assert ev.allowed_read("light.k")
    assert ev.allowed_control("light.k")


def test_read_does_not_imply_control():
    p = _policy("user: { id: a }\nallow: { entities: [ { id: light.k, access: read } ] }")
    ev = PolicyEvaluator(p, FakeRegistry())
    assert ev.allowed_read("light.k")
    assert not ev.allowed_control("light.k")


def test_default_deny_unlisted_entity():
    p = _policy("user: { id: a }\nallow: { entities: [ { id: light.k } ] }")
    ev = PolicyEvaluator(p, FakeRegistry())
    assert not ev.allowed_read("light.other")
    assert not ev.allowed_control("light.other")


def test_domain_rule_grants_whole_domain():
    p = _policy("user: { id: a }\nallow: { domains: [ { id: light, access: control } ] }")
    ev = PolicyEvaluator(p, FakeRegistry())
    assert ev.allowed_control("light.anything")
    assert not ev.allowed_read("switch.x")


def test_area_rule_uses_registry_and_fails_closed_when_stale():
    reg = FakeRegistry(area_map={"light.lr": "living_room"})
    p = _policy("user: { id: a }\nallow: { areas: [ { id: living_room, access: read } ] }")
    ev = PolicyEvaluator(p, reg)
    assert ev.allowed_read("light.lr")

    class Stale(FakeRegistry):
        def area_of(self, entity_id):
            return None  # simulate stale => unknown area

    ev2 = PolicyEvaluator(p, Stale())
    assert not ev2.allowed_read("light.lr")


def test_filter_states_keeps_only_allowed():
    p = _policy("user: { id: a }\nallow: { entities: [ { id: light.k } ] }")
    ev = PolicyEvaluator(p, FakeRegistry())
    states = [
        {"entity_id": "light.k", "state": "on"},
        {"entity_id": "sensor.secret", "state": "42"},
        {"no_entity": True},
    ]
    kept = ev.filter_states(states)
    assert kept == [{"entity_id": "light.k", "state": "on"}]


def test_enumerable_read_entities_expands_domains():
    reg = FakeRegistry(domain_entities={"light": {"light.a", "light.b"}})
    p = _policy(
        "user: { id: a }\nallow: { entities: [ { id: sensor.x } ], "
        "domains: [ { id: light, access: read } ] }"
    )
    ev = PolicyEvaluator(p, reg)
    assert set(ev.enumerable_read_entities()) == {"sensor.x", "light.a", "light.b"}


# --- allow.token_creation ----------------------------------------------------


def test_token_creation_defaults_off_for_policies_written_before_the_field():
    # Backward compatibility: this is byte-for-byte a policy file that predates
    # the field. It must keep meaning exactly what it meant then — no grant.
    p = _policy("user: { id: a }\nallow: { entities: [ { id: light.k } ] }")
    assert p.token_creation is False


def test_token_creation_true_is_parsed():
    p = _policy("user: { id: a }\nallow: { token_creation: true }")
    assert p.token_creation is True


def test_token_creation_false_is_parsed():
    p = _policy("user: { id: a }\nallow: { token_creation: false }")
    assert p.token_creation is False


@pytest.mark.parametrize("value", ["'true'", "'yes'", "1", "[]", "{}"])
def test_reject_non_boolean_token_creation(value):
    # A quoted or numeric value is a typo, not a grant. Refuse to start rather
    # than let something truthy-looking read as an authorization.
    with pytest.raises(PolicyError, match="token_creation must be a boolean"):
        _policy(f"user: {{ id: a }}\nallow: {{ token_creation: {value} }}")


def test_token_creation_does_not_widen_entity_access():
    # The grant is about the caller's own account, never about entities.
    p = _policy("user: { id: a }\nallow: { token_creation: true }")
    ev = PolicyEvaluator(p, FakeRegistry())
    assert not ev.allowed_read("light.anything")
    assert not ev.allowed_control("light.anything")
    assert ev.enumerable_read_entities() == []


def test_token_creation_round_trips_through_the_editor_dict():
    # to_editor_dict feeds the admin panel; if the field were missing there the
    # panel would silently save it back as off.
    on = _policy("user: { id: a }\nallow: { token_creation: true }")
    off = _policy("user: { id: b }\nallow: {}")
    assert on.to_editor_dict()["token_creation"] is True
    assert off.to_editor_dict()["token_creation"] is False


def test_policy_store_matches_by_id_then_name():
    by_id = _policy("user: { id: uid1 }\nallow: {}", "id.yaml")
    by_name = _policy("user: { name: Bob }\nallow: {}", "name.yaml")
    store = PolicyStore([by_id, by_name])
    assert store.find(Identity("uid1", "Whoever", False, False)) is by_id
    assert store.find(Identity("other", "Bob", False, False)) is by_name
    assert store.find(Identity("nope", "Nobody", False, False)) is None
