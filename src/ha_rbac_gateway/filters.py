"""Pure filtering helpers shared by the REST and WS proxies.

Kept side-effect free and independent of aiohttp so they are trivial to unit
test. Every function is written to fail closed: when a target cannot be fully
resolved to a set of allowed entities, the caller denies.
"""

from __future__ import annotations

from .policy import PolicyEvaluator

# Home config fields that reveal the household's physical location. A restricted
# user needs get_config for the frontend to work, but not the home's GPS.
_CONFIG_REDACT_KEYS = ("latitude", "longitude", "elevation")


def redact_home_location(config: dict) -> dict:
    """Return a copy of an HA config dict with GPS coordinates zeroed out."""
    if not isinstance(config, dict):
        return config
    redacted = dict(config)
    for key in _CONFIG_REDACT_KEYS:
        if key in redacted:
            redacted[key] = 0
    return redacted


def resolve_service_targets(
    domain: str,
    service: str,
    service_data: dict | None,
    target: dict | None,
) -> tuple[set[str], list[str]]:
    """Return (entity_ids, unresolved) for a service call.

    `entity_ids` is the concrete set of entities the call would act on.
    `unresolved` lists target kinds we cannot expand to entities here
    (device_id / area_id / label_id, or a wildcard) — their presence means the
    caller must DENY unless it resolves them via the registry.

    A call with neither entities nor unresolved targets is a domain-wide call
    (e.g. `homeassistant.restart` or `light.turn_on` with no target) — we return
    empty entity set AND a sentinel unresolved marker so the caller denies it.
    """
    entities: set[str] = set()
    unresolved: list[str] = []

    def collect(container: dict | None) -> None:
        if not isinstance(container, dict):
            return
        raw = container.get("entity_id")
        if isinstance(raw, str):
            if raw in ("all", "none"):
                unresolved.append(f"entity_id={raw}")
            else:
                entities.add(raw)
        elif isinstance(raw, list):
            for e in raw:
                if isinstance(e, str):
                    entities.add(e)
        for key in ("device_id", "area_id", "label_id", "floor_id"):
            if container.get(key):
                unresolved.append(key)

    collect(service_data)
    collect(target)

    if not entities and not unresolved:
        unresolved.append("<no-target>")  # domain-wide call — never allowed for restricted users
    return entities, unresolved


def service_call_allowed(
    evaluator: PolicyEvaluator,
    domain: str,
    service: str,
    service_data: dict | None,
    target: dict | None,
    resolve_area_device,
) -> tuple[bool, str]:
    """Decide a call_service request. Returns (allowed, reason).

    `resolve_area_device(kind, value) -> set[str] | None` expands an area/device
    target to entity ids using the registry, or returns None when it cannot
    (stale registry / unknown) — in which case we deny.
    """
    entities, unresolved = resolve_service_targets(domain, service, service_data, target)

    # Try to expand structured targets (area_id/device_id) via the registry.
    expandable = {"area_id", "device_id"}
    for kind in list(unresolved):
        if kind in expandable:
            values = []
            for container in (service_data, target):
                if isinstance(container, dict) and container.get(kind):
                    v = container[kind]
                    values.extend(v if isinstance(v, list) else [v])
            resolved_all = True
            for v in values:
                got = resolve_area_device(kind, v)
                if got is None:
                    resolved_all = False
                    break
                entities |= got
            if resolved_all:
                unresolved.remove(kind)

    if unresolved:
        return False, f"unresolvable target(s) {unresolved} — deny (fail closed)"
    if not entities:
        return False, "no concrete entity target"
    forbidden = sorted(e for e in entities if not evaluator.allowed_control(e))
    if forbidden:
        return False, f"control not permitted for {forbidden}"
    return True, f"control ok for {sorted(entities)}"


def filter_compressed_entities_event(event: dict, allowed) -> dict | None:
    """Filter a subscribe_entities compressed event.

    Compressed events use keys: 'a' (added/all), 'c' (changed), 'r' (removed).
    We drop any entity id not in `allowed`. Returns the pruned event, or None if
    nothing survives (caller should then skip relaying the frame).
    """
    out: dict = {}
    for key in ("a", "c"):
        section = event.get(key)
        if isinstance(section, dict):
            kept = {eid: v for eid, v in section.items() if allowed(eid)}
            if kept:
                out[key] = kept
    removed = event.get("r")
    if isinstance(removed, list):
        kept_r = [eid for eid in removed if allowed(eid)]
        if kept_r:
            out["r"] = kept_r
    return out or None


def state_changed_allowed(event: dict, allowed) -> bool:
    """Whether a state_changed event may be relayed (its entity is readable)."""
    data = event.get("data")
    if not isinstance(data, dict):
        return False
    eid = data.get("entity_id")
    return isinstance(eid, str) and allowed(eid)
