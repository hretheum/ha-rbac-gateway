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


def _entry_entity_id(entry: dict) -> str | None:
    # list_for_display uses abbreviated keys; "ei" is the entity_id there.
    return entry.get("entity_id") or entry.get("ei")


def filter_entity_registry(entries: list, allowed_entities: set) -> list:
    """Keep only entity-registry entries for entities the user may read."""
    if not isinstance(entries, list):
        return []
    return [e for e in entries if isinstance(e, dict) and _entry_entity_id(e) in allowed_entities]


def filter_entity_registry_display(result: dict, allowed_entities: set) -> dict:
    """Filter the {entity_categories, entities:[...]} list_for_display payload."""
    if not isinstance(result, dict):
        return {"entity_categories": [], "entities": []}  # fail closed on bad shape
    out = dict(result)
    out["entities"] = filter_entity_registry(result.get("entities", []), allowed_entities)
    return out


def filter_by_key(entries: list, key: str, allowed_ids: set) -> list:
    """Generic: keep registry entries whose `key` is in `allowed_ids`."""
    if not isinstance(entries, list):
        return []
    return [e for e in entries if isinstance(e, dict) and e.get(key) in allowed_ids]


def filter_lovelace_dashboards(dashboards: list, allowed_dashboards: set) -> list:
    """Keep only the lovelace dashboards the user may open, by `url_path`.

    `lovelace/dashboards/list` returns every storage-mode dashboard on the
    instance; forwarding it verbatim would reveal the existence (and titles) of
    dashboards the user has no access to. The built-in 'Overview' (url_path
    'lovelace') is not part of this list — it is the implicit default and is
    aliased into the panel list by `filter_panels`. Fails closed to [] on a bad
    shape.
    """
    if not isinstance(dashboards, list):
        return []
    return [
        d for d in dashboards if isinstance(d, dict) and d.get("url_path") in allowed_dashboards
    ]


# HA's frontend router falls back to a panel named this when the browser has no
# stored default. We must keep or synthesize it or navigation breaks.
DEFAULT_PANEL_KEY = "lovelace"


# Built-in panels that carry no dashboard content but are needed by the router
# (route fallback, redirects) or for account management. Kept regardless of
# policy; the admin-only ones (config, developer-tools) are hidden by the
# frontend for non-admins anyway, and feature panels (history, energy, media…)
# are intentionally NOT here so they stay out of a restricted user's sidebar.
_ESSENTIAL_COMPONENTS = ("profile", "notfound", "my")


def filter_panels(
    panels: dict,
    allowed_dashboards: set,
    default_dashboard: str | None,
    keep_components: tuple = _ESSENTIAL_COMPONENTS,
) -> dict:
    """Keep only the user's dashboards (plus a few essential built-ins like the
    profile page), so the sidebar shows nothing the user can't open.

    The router still needs a default panel (`lovelace`). If the user has no such
    dashboard, we alias their default dashboard to it as a hidden entry, so the
    default route resolves without exposing an extra sidebar item.
    """
    if not isinstance(panels, dict):
        return panels
    kept = {}
    for key, panel in panels.items():
        if not isinstance(panel, dict):
            continue
        if (
            panel.get("url_path") in allowed_dashboards
            or panel.get("component_name") in keep_components
        ):
            kept[key] = panel
    if DEFAULT_PANEL_KEY not in kept and default_dashboard and default_dashboard in panels:
        alias = dict(panels[default_dashboard])
        alias["url_path"] = DEFAULT_PANEL_KEY
        alias["show_in_sidebar"] = False
        kept[DEFAULT_PANEL_KEY] = alias
    return kept
