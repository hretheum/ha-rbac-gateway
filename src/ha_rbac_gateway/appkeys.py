"""Typed aiohttp application keys (kept dependency-light to avoid import cycles)."""

from __future__ import annotations

from aiohttp import web

# Value is a server.Gateway; typed as object here so this module imports nothing
# heavy and cannot create an import cycle with server.py / ws_proxy.py.
GATEWAY: web.AppKey[object] = web.AppKey("gateway", object)
