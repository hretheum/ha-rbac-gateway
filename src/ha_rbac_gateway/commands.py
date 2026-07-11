"""The allowlist: the single source of truth for what the gateway understands.

Everything here is DEFAULT-DENY. A REST path or WS command that is not matched
by one of these tables is denied for restricted users, never forwarded. Adding
an entry is a deliberate act that must come with a filtering strategy (see
CONTRIBUTING.md / SECURITY.md).
"""

from __future__ import annotations

# --- WebSocket -------------------------------------------------------------

# Commands forwarded verbatim; their results carry no per-entity state (frontend
# plumbing, config, translations, identity). Kept intentionally small.
WS_FORWARD_PLAIN: frozenset[str] = frozenset({
    "ping",
    "get_services",
    "manifest/list",
    "manifest/get",
    "auth/current_user",
    "frontend/get_translations",
    "frontend/get_version",
    "frontend/get_user_data",
    "frontend/set_user_data",
    "frontend/get_themes",
})

# Commands the gateway must post-process. Handlers live in ws_proxy.
WS_GET_STATES = "get_states"                # filter result list
WS_GET_CONFIG = "get_config"                # redact home GPS from result
WS_SUBSCRIBE_ENTITIES = "subscribe_entities"  # rewrite entity_ids + filter stream
WS_SUBSCRIBE_EVENTS = "subscribe_events"    # only state_changed (filtered) + safe config events
WS_CALL_SERVICE = "call_service"            # enforce target subset of control set
WS_GET_PANELS = "get_panels"                # filter to allowed dashboards
WS_LOVELACE_CONFIG = "lovelace/config"      # restrict to allowed dashboards
WS_LOVELACE_RESOURCES = "lovelace/resources"  # static resource list; forward

WS_HANDLED: frozenset[str] = frozenset({
    WS_GET_STATES, WS_GET_CONFIG, WS_SUBSCRIBE_ENTITIES, WS_SUBSCRIBE_EVENTS,
    WS_CALL_SERVICE, WS_GET_PANELS, WS_LOVELACE_CONFIG, WS_LOVELACE_RESOURCES,
})

# subscribe_events: event types that carry no entity state and only tell the UI
# to refetch. state_changed is handled specially (per-entity filtering).
WS_SAFE_EVENT_TYPES: frozenset[str] = frozenset({
    "lovelace_updated",
    "panels_updated",
    "themes_updated",
    "core_config_updated",
})

# Explicitly dangerous — denied even though a naive blocklist reader might miss
# them, because each can read or act on entities outside an entity allowlist.
# (Documented here for auditors; enforcement is simply "not in the allowlist".)
WS_EXPLICIT_DENY: frozenset[str] = frozenset({
    "render_template",
    "execute_script",
    "subscribe_trigger",
    "fire_event",
    "config/entity_registry/list",
    "config/entity_registry/list_for_display",
    "config/device_registry/list",
    "config/area_registry/list",
    "config/auth/list",
    "config/auth/create",
    "config/auth/update",
    "config/auth/delete",
    "config/auth_provider/homeassistant/create",
    "history/history_during_period",
    "history/stream",
    "logbook/get_events",
    "logbook/event_stream",
    "camera/stream",
    "media_source/browse_media",
})


# --- REST ------------------------------------------------------------------

# GET endpoints whose response we filter or that carry no entity state.
# Anything not listed under one of the REST rules is denied.
REST_ALLOW_GET_PLAIN: frozenset[str] = frozenset({
    "/api/",          # HA "API running" ping
    "/api/services",  # service catalogue (no states)
})
# /api/config is allowed but its response is redacted (home GPS removed), so it
# is handled explicitly rather than passed through plain.

# Path prefixes for the static frontend shell, forwarded as-is on GET. These
# serve HTML/JS/CSS with no entity data; live data still flows only through the
# filtered /api/ + WS surface.
REST_FRONTEND_PREFIXES: tuple[str, ...] = (
    "/frontend_latest/",
    "/frontend_es5/",
    "/static/",
    "/hacsfiles/",
    "/local/",
    "/service_worker.js",
    "/manifest.json",
    "/authorize.html",
    "/onboarding.html",
)

# Auth endpoints (login flow, token exchange, revoke). No entity state; required
# for a user to obtain a token. Forwarded as-is.
REST_AUTH_PREFIX = "/auth/"

# Explicitly denied REST endpoints (documented for auditors).
REST_EXPLICIT_DENY_PREFIXES: tuple[str, ...] = (
    "/api/template",
    "/api/error_log",
    "/api/history/",
    "/api/logbook/",
    "/api/camera_proxy/",
    "/api/calendars",
    "/api/events/",       # fire arbitrary events
    "/api/config/",       # config admin surface
)
