"""304 归属失败路径、普通文件兼容性与 SQLite 台账/幂等测试。"""

from __future__ import annotations

import json
import sqlite3

import pytest

from decodebench.ledger_queries import list_validation_events
from decodebench.pipeline import _process_ordinary_file, run
from decodebench.scanner import is_validation_response, scan
from decodebench.validation import digest_bytes, is_strong_etag, parse_capture_state

from _validation_helpers import (
    ETAG_V1, FR, NOW, PAIR_FILES, RESOURCE, T_200, T_304, capture_tree,
    config, event_for, pair_sidecars, run_tree, scan_map, state_200, state_304,
)

def _counterexample():
    return PAIR_FILES, pair_sidecars()

def _unattributed(cfg, code, review=True):
    event = event_for("b/doc_304.html", cfg)
    assert event["status"] == "unattributed" and code in event["error_codes"]
    if review:
        assert "W_304_ATTRIBUTION_REVIEW" in event["error_codes"]
    assert event["views"] == []
    assert not (cfg.transcode_dir / "_validation_views").exists()
    return event

def _vary_missing():
    files, sidecars = PAIR_FILES, pair_sidecars()
    sidecars["b/doc_304"].pop("request_vary")
    return files, sidecars

def _conflict_entities():
    files = {"a/one_200.html": b"\xc3\xa9", "a/two_200.html": b"\xc3\xbb",
             "b/doc_304.html": b""}
    sidecars = {
        "a/one_200": state_200(T_200, FR, ETAG_V1, "text/html; charset=windows-1252"),
        "a/two_200": state_200("2024-02-01T01:00:00Z", FR, ETAG_V1,
                               "text/html; charset=windows-1252"),
        "b/doc_304": state_304(T_304, FR, ETAG_V1,
                               {"Content-Type": "text/html; charset=windows-1252"})}
    return files, sidecars

def _wrong_resource_key():
    # 同目录、文件名最近、ETag 相同，但资源键不同：禁止就近冒充正文
    files = {"b/doc_200.html": b"other-language-body", "b/doc_304.html": b""}
    sidecars = {
        "b/doc_200": state_200(T_200, FR, ETAG_V1, "text/html; charset=utf-8",
                               resource_key="http://example.invalid/captures/other"),
        "b/doc_304": state_304(T_304, FR, ETAG_V1,
                               {"Content-Type": "text/html; charset=utf-8"},
                               resource_key=RESOURCE)}
    return files, sidecars

def _empty_entity():
    files = dict(PAIR_FILES)
    files["a/doc_200.html"] = b""  # 零字节 200 不是可复用实体
    return files, pair_sidecars()

@pytest.mark.parametrize("builder,code,review", [
    (_vary_missing, "E_304_VARY_INPUT_MISSING", False),
    (lambda: (PAIR_FILES, pair_sidecars(etag_200='W/"v1"', etag_304='W/"v1"')),
     "E_304_WEAK_VALIDATOR", True),
    (_conflict_entities, "E_304_ENTITY_CONFLICT", True),
    (lambda: (PAIR_FILES, pair_sidecars(etag_304='"v2"')),
     "E_304_ETAG_MISMATCH", True),
    (lambda: ({"b/doc_304.html": b""}, {"b/doc_304": state_304(
        T_304, FR, ETAG_V1, {"Content-Type": "text/html; charset=utf-8"})}),
     "E_304_NO_CANDIDATE_200", True),
    (_wrong_resource_key, "E_304_NO_CANDIDATE_200", True),
    (_empty_entity, "E_304_ORIGINAL_UNREADABLE", True),
])
def test_304_attribution_failures_keep_evidence_without_fake_text(
        capture_tree, make_config, builder, code, review):
    cfg = run_tree(make_config, capture_tree, *builder())
    event = _unattributed(cfg, code, review=review)
    if code == "E_304_ENTITY_CONFLICT":
        assert set(event["candidate_rel_paths"]) == {
            "a/one_200.html", "a/two_200.html"}
    if code == "E_304_NO_CANDIDATE_200" and builder is _wrong_resource_key:
        assert event["donor_rel_path"] is None and event["entity_sha256"] is None

def test_unmarked_304_remains_per_file_flow(capture_tree, make_config):
    files = {"a/plain.txt": b"hello", "b/empty_304.txt": b""}
    sidecars = {"b/empty_304": {
        "status": 304, "url": RESOURCE,
        "headers": {"Content-Type": "text/plain; charset=utf-8"}}}
    cfg = run_tree(make_config, capture_tree, files, sidecars)
    manifest = json.loads(cfg.manifest_path.read_text(encoding="utf-8"))
    assert manifest["validation_events"] == []
    assert {i["rel_path"] for i in manifest["files"]} == {
        "a/plain.txt", "b/empty_304.txt"}
    assert is_validation_response(scan_map(cfg)["b/empty_304.txt"]) is False

def test_ordinary_sidecar_without_state_uses_existing_flow(make_config):
    assert all(not is_validation_response(i) for i in scan(make_config()))

def test_sqlite_records_two_views_and_is_idempotent(capture_tree, make_config):
    cfg = config(make_config, capture_tree(*_counterexample()))
    first, second = run(cfg, NOW), run(cfg, NOW)
    assert first["batch_id"] == second["batch_id"]
    assert first["ledger"]["validation_event_rows"] == 1
    assert first["ledger"]["validation_view_rows"] == 2
    events = list_validation_events(cfg.db_path, first["batch_id"])
    assert len(events) == 1
    event = events[0]
    assert event["rel_path_304"] == "b/doc_304.html"
    assert event["entity_sha256"] == digest_bytes(b"\xc3\xa9")
    contracts = {row["contract"]: row for row in event["views"]}
    assert set(contracts) == {"forensic_original", "refreshed_view"}
    assert contracts["forensic_original"]["published"] == 1
    assert contracts["refreshed_view"]["published"] == 1
    connection = sqlite3.connect(cfg.db_path)
    try:
        counts = [connection.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                  for t in ("validation_events", "validation_views")]
    finally:
        connection.close()
    assert counts == [1, 2]

def test_unattributed_event_lands_in_sqlite_without_views(capture_tree, make_config):
    sidecars = {"b/doc_304": state_304(
        T_304, FR, ETAG_V1, {"Content-Type": "text/html; charset=utf-8"})}
    cfg = config(make_config, capture_tree({"b/doc_304.html": b""}, sidecars))
    events = list_validation_events(cfg.db_path, run(cfg, NOW)["batch_id"])
    assert len(events) == 1
    assert events[0]["status"] == "unattributed" and events[0]["views"] == []
    assert json.loads(events[0]["request_vary_json"]) == FR

def test_strong_etag_and_state_shape_contracts():
    assert [is_strong_etag(v) for v in ('"v1"', 'W/"v1"', "", None, "v1")] == [
        True, False, False, False, False]
    state, errors = parse_capture_state({"status": 304, "headers": {}})
    assert state is None and "E_304_NOT_STATE_SIDECAR" in errors
    state, errors = parse_capture_state({
        "local_capture": True, "status": 304, "resource_key": "r",
        "captured_at": "not-a-timestamp", "request_vary": FR,
        "etag": '"v1"', "headers": {}})
    assert state is None and "E_304_MALFORMED_STATE" in errors

def test_process_validation_event_entrypoint_is_offline(capture_tree, make_config):
    """直接调用公开入口，确认它只依赖扫描结果与本地字节。"""
    from decodebench.pipeline_validation import process_validation_event

    cfg = config(make_config, capture_tree(*_counterexample()))
    sources = scan(cfg)
    source_304 = next(i for i in sources if i.rel_path == "b/doc_304.html")
    donor_entry = _process_ordinary_file(
        next(i for i in sources if i.rel_path == "a/doc_200.html"), cfg)
    event = process_validation_event(
        source_304, sources, {"a/doc_200.html": donor_entry}, cfg)
    assert event["status"] == "attributed"
    assert {v["contract"] for v in event["views"]} == {
        "forensic_original", "refreshed_view"}
    assert event["entity_sha256"] == digest_bytes(b"\xc3\xa9")
    assert event["sidecar_200_sha256"] and event["sidecar_304_sha256"]
