"""Shared value types."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Identity:
    """Who a token belongs to, as reported by Home Assistant itself."""

    user_id: str
    name: str
    is_admin: bool
    is_owner: bool


class GatewayDenied(Exception):
    """Internal signal: request must be denied. Carries an audit reason."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason
