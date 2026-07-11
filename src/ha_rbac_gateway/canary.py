"""Canary self-test: proves filtering still works, trips the gateway if it does not.

The canary uses a real restricted token (a test user's long-lived token) and
asks the gateway — through its own public port, exactly like a browser — two
questions on a schedule:

  1. Can I read the entity I am ALLOWED to read?  (must be yes)
  2. Am I correctly DENIED a known-forbidden entity and a forbidden command?
     (must be denied)

If a forbidden entity ever becomes visible, or a denied command starts being
answered, the canary trips the gateway (fail closed) so an HA change that breaks
filtering causes a lockout, never a silent leak.

Run modes:
- background task inside the gateway process (when CANARY_TOKEN is set), and
- `python -m ha_rbac_gateway.canary` as a standalone one-shot for CI / cron.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys

import aiohttp

log = logging.getLogger(__name__)


class CanaryResult:
    def __init__(self):
        self.checks: list[tuple[str, bool, str]] = []

    def record(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append((name, ok, detail))

    @property
    def ok(self) -> bool:
        return all(ok for _, ok, _ in self.checks)

    def report(self) -> str:
        return "\n".join(
            f"  [{'PASS' if ok else 'FAIL'}] {name}{f' — {d}' if d else ''}"
            for name, ok, d in self.checks
        )


async def run_canary(
    gateway_base: str,
    token: str,
    allowed_entity: str,
    forbidden_entity: str,
) -> CanaryResult:
    """Exercise the gateway's own port with a restricted token. Pure check; no trip."""
    r = CanaryResult()
    headers = {"Authorization": f"Bearer {token}"}
    timeout = aiohttp.ClientTimeout(total=15)
    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as s:
        # 1. allowed entity readable via REST
        if allowed_entity:
            async with s.get(f"{gateway_base}/api/states/{allowed_entity}") as resp:
                r.record("read allowed entity (REST)", resp.status == 200,
                         f"status={resp.status}")

        # 2. forbidden entity denied via REST
        async with s.get(f"{gateway_base}/api/states/{forbidden_entity}") as resp:
            r.record("forbidden entity denied (REST)", resp.status == 403,
                     f"status={resp.status}")

        # 3. template endpoint denied (state-exfiltration vector)
        async with s.post(f"{gateway_base}/api/template",
                          json={"template": "{{ states('" + forbidden_entity + "') }}"}) as resp:
            r.record("template endpoint denied (REST)", resp.status == 403,
                     f"status={resp.status}")

        # 4. WS: get_states must not include the forbidden entity; render_template denied
        await _ws_checks(s, gateway_base, token, forbidden_entity, r)
    return r


async def _ws_checks(session, gateway_base, token, forbidden_entity, r: CanaryResult) -> None:
    ws_url = gateway_base.replace("http", "ws", 1) + "/api/websocket"
    try:
        async with session.ws_connect(ws_url) as ws:
            await ws.receive_json()  # auth_required
            await ws.send_json({"type": "auth", "access_token": token})
            auth = await ws.receive_json()
            if auth.get("type") != "auth_ok":
                r.record("ws auth", False, f"got {auth.get('type')}")
                return
            await ws.send_json({"id": 1, "type": "get_states"})
            states = await _await_result(ws, 1)
            visible = {s.get("entity_id") for s in (states.get("result") or [])}
            r.record("forbidden entity absent from ws get_states",
                     forbidden_entity not in visible,
                     f"{len(visible)} visible")
            await ws.send_json({"id": 2, "type": "render_template",
                                "template": "{{ states('" + forbidden_entity + "') }}"})
            rt = await _await_result(ws, 2)
            r.record("ws render_template denied", rt.get("success") is False,
                     f"error={rt.get('error', {}).get('code')}")
            await ws.send_json({"id": 3, "type": "totally/unknown_gateway_probe"})
            uk = await _await_result(ws, 3)
            r.record("ws unknown command denied", uk.get("success") is False,
                     f"error={uk.get('error', {}).get('code')}")
    except Exception as exc:
        r.record("ws checks", False, f"exception: {exc}")


async def _await_result(ws, mid: int) -> dict:
    while True:
        m = await ws.receive_json()
        if m.get("id") == mid and m.get("type") == "result":
            return m


class CanaryRunner:
    """Background loop; trips the gateway on any failure."""

    def __init__(self, gw):
        self.gw = gw
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        cfg = self.gw.config
        if not cfg.canary_token:
            log.info("canary disabled (no CANARY_TOKEN)")
            return
        self._task = asyncio.create_task(self._loop(), name="canary")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _loop(self) -> None:
        cfg = self.gw.config
        base = f"http://127.0.0.1:{cfg.listen_port}"
        await asyncio.sleep(10)  # let the listener settle
        while True:
            try:
                result = await run_canary(base, cfg.canary_token,
                                          cfg.canary_allowed_read_entity,
                                          cfg.canary_forbidden_entity)
                if result.ok:
                    log.info("canary OK\n%s", result.report())
                else:
                    self.gw.trip.trip(f"canary failed:\n{result.report()}")
            except Exception as exc:
                log.warning("canary run errored (not tripping on infra error): %s", exc)
            await asyncio.sleep(cfg.canary_interval)


async def _main() -> int:
    import os
    base = os.environ.get("GATEWAY_BASE", "http://127.0.0.1:8124")
    token = os.environ.get("CANARY_TOKEN", "")
    allowed = os.environ.get("CANARY_ALLOWED_READ_ENTITY", "")
    forbidden = os.environ.get("CANARY_FORBIDDEN_ENTITY", "sun.sun")
    if not token:
        print("CANARY_TOKEN required", file=sys.stderr)
        return 2
    result = await run_canary(base, token, allowed, forbidden)
    print(json.dumps({"ok": result.ok,
                      "checks": [{"name": n, "ok": o, "detail": d} for n, o, d in result.checks]},
                     indent=2))
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
