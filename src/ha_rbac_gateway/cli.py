"""Entry point: `ha-rbac-gateway` / `python -m ha_rbac_gateway`."""

from __future__ import annotations

import logging

from aiohttp import web

from .config import ConfigError, load_config
from .server import build_app


def main() -> None:
    try:
        config = load_config()
    except ConfigError as exc:
        raise SystemExit(f"configuration error: {exc}") from exc

    logging.basicConfig(
        level=getattr(logging, config.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    app = build_app(config)
    web.run_app(app, host=config.listen_host, port=config.listen_port, print=None)


if __name__ == "__main__":
    main()
