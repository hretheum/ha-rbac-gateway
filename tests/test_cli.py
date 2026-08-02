"""The entry point itself, not a test-local imitation of it."""

import sys

import pytest
from aiohttp import web

from ha_rbac_gateway import cli


@pytest.fixture
def run_app_kwargs(monkeypatch, tmp_path):
    """Run `cli.main()` with the listener stubbed out; yields its kwargs."""
    captured: dict = {}
    monkeypatch.setattr(web, "run_app", lambda app, **kwargs: captured.update(kwargs))
    monkeypatch.setattr(sys, "argv", ["ha-rbac-gateway"])
    monkeypatch.setenv("HA_URL", "http://127.0.0.1:8123")
    monkeypatch.setenv("HA_TOKEN", "backend")
    monkeypatch.setenv("POLICY_DIR", str(tmp_path / "policies"))
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    (tmp_path / "policies").mkdir()
    cli.main()
    return captured


def test_main_installs_the_redacting_access_logger(run_app_kwargs):
    # The tests' own fixture passes this to its TestServer, which proves the
    # class works but NOT that production uses it — a refactor could drop the
    # argument here and every other test would still pass while real
    # deployments went back to logging tokens.
    assert run_app_kwargs["access_log_class"] is cli.PathOnlyAccessLogger


def test_main_binds_the_configured_listener(run_app_kwargs):
    assert run_app_kwargs["host"] == "0.0.0.0"  # noqa: S104 - LISTEN_HOST default
    assert run_app_kwargs["port"] == 8124
