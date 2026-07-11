"""Structured, token-free audit logging of every allow/deny decision.

One line per decision. Never log tokens or request bodies; entity ids,
command types and user ids are enough for forensics.
"""

from __future__ import annotations

import logging

from .model import Identity

log = logging.getLogger("ha_rbac_gateway.audit")


def _who(identity: Identity | None) -> str:
    if identity is None:
        return "user=<unauthenticated>"
    return f"user={identity.user_id}({identity.name})"


def allow(identity: Identity | None, channel: str, what: str, detail: str = "") -> None:
    log.info("ALLOW %s %s %s %s", _who(identity), channel, what, detail)


def deny(identity: Identity | None, channel: str, what: str, reason: str) -> None:
    log.warning("DENY %s %s %s reason=%s", _who(identity), channel, what, reason)
