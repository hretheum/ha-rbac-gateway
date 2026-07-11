"""Gateway configuration, loaded exclusively from environment variables.

Nothing deployment-specific is ever hardcoded: the HA base URL, the backend
token and all paths come from the environment (see .env.example).
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlparse


class ConfigError(Exception):
    """Raised when the environment does not describe a usable configuration."""


def _int(src: Mapping[str, str], name: str, default: int) -> int:
    raw = src.get(name, "")
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc


@dataclass(frozen=True)
class GatewayConfig:
    # Upstream Home Assistant
    ha_url: str  # e.g. http://127.0.0.1:8123 (no trailing slash)
    ha_token: str  # long-lived access token used ONLY for registry/identity plumbing

    # Listener
    listen_host: str
    listen_port: int

    # Filesystem
    policy_dir: str  # directory of per-user policy YAML files
    data_dir: str  # writable dir; holds the canary trip file

    # Behaviour tuning
    identity_cache_ttl: int  # seconds a token->identity mapping is cached
    registry_refresh_interval: int  # seconds between registry refreshes
    registry_stale_max: int  # registry older than this => area rules fail closed

    # Canary (optional; enabled when canary_token is set)
    canary_token: str
    canary_interval: int
    canary_allowed_read_entity: str
    canary_forbidden_entity: str

    log_level: str

    @property
    def ha_ws_url(self) -> str:
        scheme = "wss" if self.ha_url.startswith("https") else "ws"
        return f"{scheme}://{self.ha_url.split('://', 1)[1]}/api/websocket"

    @property
    def trip_file(self) -> str:
        return os.path.join(self.data_dir, "tripped")


def load_config(env: Mapping[str, str] | None = None) -> GatewayConfig:
    """Build config from `env` (a mapping) or, by default, the process env."""
    src: Mapping[str, str] = os.environ if env is None else env

    ha_url = src.get("HA_URL", "").rstrip("/")
    ha_token = src.get("HA_TOKEN", "")
    if not ha_url:
        raise ConfigError("HA_URL is required (e.g. http://127.0.0.1:8123)")
    parsed = urlparse(ha_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ConfigError(f"HA_URL must be an http(s) URL, got {ha_url!r}")
    if not ha_token:
        raise ConfigError("HA_TOKEN is required (a long-lived access token; keep it in .env)")

    return GatewayConfig(
        ha_url=ha_url,
        ha_token=ha_token,
        listen_host=src.get("LISTEN_HOST", "0.0.0.0"),  # noqa: S104 — this is a server
        listen_port=_int(src, "LISTEN_PORT", 8124),
        policy_dir=src.get("POLICY_DIR", "/config/policies"),
        data_dir=src.get("DATA_DIR", "/data"),
        identity_cache_ttl=_int(src, "IDENTITY_CACHE_TTL", 300),
        registry_refresh_interval=_int(src, "REGISTRY_REFRESH_INTERVAL", 300),
        registry_stale_max=_int(src, "REGISTRY_STALE_MAX", 900),
        canary_token=src.get("CANARY_TOKEN", ""),
        canary_interval=_int(src, "CANARY_INTERVAL", 21600),
        canary_allowed_read_entity=src.get("CANARY_ALLOWED_READ_ENTITY", ""),
        canary_forbidden_entity=src.get("CANARY_FORBIDDEN_ENTITY", "sun.sun"),
        log_level=src.get("LOG_LEVEL", "INFO").upper(),
    )
