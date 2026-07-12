# Troubleshooting

Symptom → likely cause → fix. Most first-time issues are about **reachability**
(who can reach which port) rather than the gateway's logic.

## `docker compose up` / the Quadlet fails to start on an image pull

**Cause:** the public multi-arch image at `ghcr.io/hretheum/ha-rbac-gateway`
can't be reached — usually you're offline or behind a registry-blocking proxy.

**Fix:** build it locally under the tag the deploy files expect, then start:

```bash
docker build -t ghcr.io/hretheum/ha-rbac-gateway:latest .   # or: podman build ...
```

## Admin panel shows "Could not reach the gateway admin API"

The panel runs in your browser (on HA's origin) and calls the gateway on a
different port — a cross-origin request. It fails for one of these reasons:

- **Mixed content.** If you open HA over **https** (Nabu Casa, a TLS reverse
  proxy) but `gateway_base` is `http://…:8124`, the browser silently blocks the
  http call from an https page. Open the browser DevTools console to confirm.
  Fix: use plain http on the LAN for both, or put TLS in front of the gateway
  too and set `gateway_base` to its https URL.
- **Firewall.** The gateway port must be reachable from the admin's device, not
  just from `localhost` (see the next entry).
- **Wrong `gateway_base`.** It must be the URL of the gateway as *your browser*
  sees it (usually `http://<gateway-host>:8124`), set in the `panel_custom`
  `config:` block.

## Reachable from the host (`curl localhost:8124`) but not from another device

**Cause:** the host firewall allows HA's port but not the gateway's. This is the
single most common "it works locally but my phone/browser can't reach it".

**Fix:** allow the gateway port for your LAN. For example with `ufw`:

```bash
sudo ufw allow from 192.168.0.0/16 to any port 8124 proto tcp
```

(Adjust the subnet/port. `firewalld`: `firewall-cmd --add-port=8124/tcp`.)

## A restricted user's dashboard shows cards as "unavailable"

**Cause:** the user can *open* the dashboard, but the entities it references are
not in their policy, so their state is filtered out.

**Fix:** grant the entities (or their area/domain) in the user's policy — access
to a dashboard and access to its entities are separate.

## Blank or garbled frontend only when there's another reverse proxy in front

**Cause:** the gateway relays upstream `Content-Encoding` (brotli/gzip) as-is for
a byte-for-byte passthrough. A second proxy that re-compresses can double-encode.

**Fix:** don't re-compress the gateway's responses in the outer proxy (it already
relays HA's compression), or terminate compression in exactly one place.

## (Contributors) a new allowlist entry behaves oddly under load

**Cause:** Home Assistant can **coalesce** several WebSocket messages into a
single JSON-array frame. Message handling must accept both a single object and an
array of them.

**Fix:** see `docs/architecture.md` ("Serving the Home Assistant frontend") and
the coalescing test in `tests/conftest.py`.
