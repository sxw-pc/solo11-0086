"""304 离线验证测试共享的合成 sidecar/采集目录夹具与断言助手。"""

from __future__ import annotations

import json

import pytest

from decodebench.pipeline import run
from decodebench.scanner import scan

RESOURCE = "http://example.invalid/captures/doc"
ETAG_V1 = '"v1"'
NOW = "2024-02-03T00:00:00Z"
FR = {"accept-language": "fr"}
T_200 = "2024-02-01T00:00:00Z"
T_304 = "2024-02-02T00:00:00Z"
PAIR_FILES = {"a/doc_200.html": b"\xc3\xa9", "b/doc_304.html": b""}

def _state(status, captured_at, vary, etag, headers, resource_key=RESOURCE):
    return {"local_capture": True, "status": status, "url": resource_key,
            "resource_key": resource_key, "captured_at": captured_at,
            "request_vary": vary, "etag": etag, "headers": headers}

def state_200(captured_at, vary, etag, content_type, *, resource_key=RESOURCE,
              extra_headers=None):
    headers = {"Content-Type": content_type}
    if extra_headers:
        headers.update(extra_headers)
    return _state(200, captured_at, vary, etag, headers, resource_key)

def state_304(captured_at, vary, etag, headers, *, resource_key=RESOURCE):
    return _state(304, captured_at, vary, etag, headers, resource_key)

@pytest.fixture
def capture_tree(tmp_path):
    def build(files, sidecars):
        root = tmp_path / "captures"
        root.mkdir(parents=True, exist_ok=True)
        for name, payload in files.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        for name, payload in sidecars.items():
            target = root / (name + ".headers.json")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                              encoding="utf-8")
        return root
    return build

def config(make_config, root):
    return make_config(scan_root=root, sidecar_root=root)

def run_tree(make_config, capture_tree, files, sidecars):
    cfg = config(make_config, capture_tree(files, sidecars))
    run(cfg, NOW)
    return cfg

def event_for(rel_path, cfg):
    manifest = json.loads(cfg.manifest_path.read_text(encoding="utf-8"))
    return next(e for e in manifest["validation_events"] if e["rel_path_304"] == rel_path)

def views(event):
    return {v["contract"]: v for v in event["views"]}

def scan_map(cfg):
    return {item.rel_path: item for item in scan(cfg)}

def pair_sidecars(etag_200=ETAG_V1, etag_304=ETAG_V1,
                  ct_304="text/html; charset=utf-8", vary=FR):
    return {
        "a/doc_200": state_200(T_200, vary, etag_200,
                               "text/html; charset=windows-1252"),
        "b/doc_304": state_304(T_304, vary, etag_304, {"Content-Type": ct_304})}
