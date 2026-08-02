"""Entry point: `ha-rbac-gateway` / `python -m ha_rbac_gateway`."""

from __future__ import annotations

import argparse
import logging

from aiohttp import web
from aiohttp.abc import AbstractAccessLogger

from . import __version__
from .config import ConfigError, load_config
from .server import build_app


class PathOnlyAccessLogger(AbstractAccessLogger):
    """Access log line that never carries a query string.

    HA's own clients send the access token as `?token=`/`?access_token=` on
    media URLs (see `rest_proxy._bearer`), so aiohttp's default `%r` atom — the
    request line, i.e. `request.path_qs` — would write live user tokens in clear
    text to the container log. Formatting from `request.path` drops them at the
    source; `%r` cannot be made safe by changing `access_log_format` alone.
    """

    def log(self, request: web.BaseRequest, response: web.StreamResponse, time: float) -> None:
        self.logger.info(
            '%s "%s %s" %s %s %.6f',
            request.remote or "-",
            request.method,
            request.path,
            response.status,
            response.body_length,
            time,
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="ha-rbac-gateway", description="Fail-closed RBAC gateway for Home Assistant"
    )
    parser.add_argument("--version", action="version", version=f"ha-rbac-gateway {__version__}")
    parser.parse_args()

    try:
        config = load_config()
    except ConfigError as exc:
        raise SystemExit(f"configuration error: {exc}") from exc

    logging.basicConfig(
        level=getattr(logging, config.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    app = build_app(config)
    web.run_app(
        app,
        host=config.listen_host,
        port=config.listen_port,
        print=None,
        access_log_class=PathOnlyAccessLogger,
    )


if __name__ == "__main__":
    main()
