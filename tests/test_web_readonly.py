from __future__ import annotations

import pytest

from decodebench.config import ConfigError
from decodebench.web import create_app


def test_web_binding_defaults_and_rejects_public_host(make_config):
    config = make_config()
    assert config.web_host == "127.0.0.1"
    assert config.web_port == 5017
    with pytest.raises(ConfigError):
        make_config(host="0.0.0.0")


def test_readonly_routes_and_pages(run_demo):
    config, result = run_demo()
    app = create_app(config)
    app.testing = True
    client = app.test_client()

    index = client.get("/")
    assert index.status_code == 200
    assert "只读".encode() in index.data
    assert b"<form" not in index.data.lower()

    batch = client.get(f"/batch/{result['batch_id']}")
    assert batch.status_code == 200
    assert b"gb18030_with_utf8_meta.html" in batch.data
    assert b"<form" not in batch.data.lower()

    detail = client.get(
        f"/file/{result['batch_id']}/gb18030_with_utf8_meta.html"
    )
    assert detail.status_code == 200
    assert b"meta charset" in detail.data.lower()
    assert b"E_META_BYTE_CONFLICT" in detail.data
    assert b"<form" not in detail.data.lower()

    health = client.get("/healthz")
    assert health.status_code == 200
    assert health.get_json() == {"status": "ok", "read_only": True}
    assert detail.headers["Cache-Control"] == "no-store"
    assert detail.headers["X-Content-Type-Options"] == "nosniff"
    assert "script-src 'none'" in detail.headers["Content-Security-Policy"]


def test_no_mutating_or_proxy_routes(run_demo):
    config, _ = run_demo()
    app = create_app(config)
    routes = list(app.url_map.iter_rules())
    assert routes
    for rule in routes:
        assert not (rule.methods & {"POST", "PUT", "PATCH", "DELETE"})
        text = f"{rule.endpoint} {rule.rule}".lower()
        for blocked in ("upload", "delete", "edit", "proxy", "fetch", "run"):
            assert blocked not in text
    client = app.test_client()
    assert client.post("/").status_code == 405
    assert client.delete("/").status_code == 405


def test_static_assets_are_local_and_missing_pages_404(run_demo):
    config, result = run_demo()
    client = create_app(config).test_client()
    css = client.get("/static/style.css")
    assert css.status_code == 200
    assert b"http://" not in css.data
    assert b"https://" not in css.data
    assert b"cdn" not in css.data.lower()
    assert client.get("/batch/does-not-exist").status_code == 404
    assert (
        client.get(f"/file/{result['batch_id']}/does-not-exist.txt").status_code
        == 404
    )
