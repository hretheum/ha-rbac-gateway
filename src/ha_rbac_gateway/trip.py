"""The trip switch: a file whose existence means "fail closed, deny everyone".

The canary (or an operator) creates the file when it detects that filtering can
no longer be trusted — e.g. after an HA upgrade changed API behaviour. While the
file exists the gateway denies ALL restricted traffic. Clearing it is a manual,
human decision: review what changed, then delete the file.
"""

from __future__ import annotations

import logging
import os
import time

log = logging.getLogger(__name__)


class TripSwitch:
    def __init__(self, path: str, check_interval: float = 1.0):
        self._path = path
        self._check_interval = check_interval
        self._last_check = 0.0
        self._cached = False

    @property
    def path(self) -> str:
        return self._path

    def is_tripped(self) -> bool:
        now = time.monotonic()
        if now - self._last_check >= self._check_interval:
            self._cached = os.path.exists(self._path)
            self._last_check = now
        return self._cached

    def trip(self, reason: str) -> None:
        os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')} {reason}\n")
        self._last_check = 0.0  # force re-read on next check
        log.critical("GATEWAY TRIPPED (fail closed): %s — remove %s after manual review",
                     reason, self._path)
