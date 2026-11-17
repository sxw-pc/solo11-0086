"""304 双合同视图、Vary 隔离与头部/编码矛盾的拒绝行为。"""

from __future__ import annotations

import pytest

from decodebench.validation import digest_bytes, synthesize_headers

from _validation_helpers import (
    ETAG_V1, FR, PAIR_FILES, T_200, T_304, capture_tree, event_for,
    run_tree, state_200, state_304, views,
)

DE = {"accept-language": "de"}


def _counterexample(ct_304=None, body=b"\xc3\xa9", vary=FR):
    h304 = {"Content-Type": ct_304} if ct_304 else {"ETag": ETAG_V1}
    sidecars = {
        "a/doc_200": state_200(T_200, vary, ETAG_V1, "text/html; charset=windows-1252"),
        "b/doc_304": state_304(T_304, vary, ETAG_V1, h304)}
    return {**PAIR_FILES, "a/doc_200.html": body}, sidecars


def _content_type_row(event):
    return next(r for r in event["synthesized_headers"]
                if r["name"].lower() == "content-type")


def test_minimal_counterexample_forensic_vs_refreshed(capture_tree, make_config):
    files, sidecars = _counterexample("text/html; charset=utf-8")
    cfg = run_tree(make_config, capture_tree, files, sidecars)
    event = event_for("b/doc_304.html", cfg)
    assert event["status"] == "attributed"
    assert event["donor_rel_path"] == "a/doc_200.html"
    assert event["entity_sha256"] == digest_bytes(b"\xc3\xa9")
    assert event["sidecar_200_sha256"] and event["sidecar_304_sha256"]
    assert event["sidecar_200_sha256"] != event["sidecar_304_sha256"]
    assert _content_type_row(event) == {
        "name": "Content-Type", "value": "text/html; charset=utf-8",
        "source": "status_304"}
    contract = views(event)
    forensic, refreshed = contract["forensic_original"], contract["refreshed_view"]
    assert forensic["entity_sha256"] == refreshed["entity_sha256"]
    assert forensic["published"] and refreshed["published"]
    forensic_text = (cfg.transcode_dir / forensic["view_rel_path"]).read_bytes()
    refreshed_text = (cfg.transcode_dir / refreshed["view_rel_path"]).read_bytes()
    assert forensic_text.decode("utf-8") == "Ã©"
    assert refreshed_text.decode("utf-8") == "é"
    assert forensic["output_sha256"] != refreshed["output_sha256"]
    assert refreshed["view_rel_path"].startswith("_validation_views/")
    assert (refreshed["encoding"], forensic["encoding"]) == ("utf-8", "windows-1252")
    assert not (cfg.transcode_dir / "b/doc_304.html").exists()
    assert (cfg.transcode_dir / "a/doc_200.html").is_file()


def test_no_charset_update_yields_identical_text_but_records_validation(
        capture_tree, make_config):
    cfg = run_tree(make_config, capture_tree, *_counterexample())
    event = event_for("b/doc_304.html", cfg)
    assert _content_type_row(event) == {
        "name": "Content-Type", "value": "text/html; charset=windows-1252",
        "source": "status_200"}
    contract = views(event)
    forensic_text = (cfg.transcode_dir
                     / contract["forensic_original"]["view_rel_path"]).read_bytes()
    refreshed_text = (cfg.transcode_dir
                      / contract["refreshed_view"]["view_rel_path"]).read_bytes()
    assert forensic_text == refreshed_text
    assert (contract["forensic_original"]["output_sha256"]
            == contract["refreshed_view"]["output_sha256"])
    assert (contract["forensic_original"]["header_basis"],
            contract["refreshed_view"]["header_basis"]) == (
        "status_200_original", "synthesized_304")
    assert "W_304_FORENSIC_VALIDATION" in event["error_codes"]


def test_vary_variants_do_not_cross_inherit(capture_tree, make_config):
    fr_body = "français".encode("windows-1252")
    de_body = "grüßen".encode("windows-1252")
    files = {"a/fr_200.html": fr_body, "a/de_200.html": de_body, "b/fr_304.html": b""}
    sidecars = {
        "a/fr_200": state_200(T_200, FR, ETAG_V1, "text/html; charset=windows-1252"),
        "a/de_200": state_200(T_200, DE, ETAG_V1, "text/html; charset=windows-1252"),
        "b/fr_304": state_304(T_304, FR, ETAG_V1,
                              {"Content-Type": "text/html; charset=windows-1252"})}
    cfg = run_tree(make_config, capture_tree, files, sidecars)
    event = event_for("b/fr_304.html", cfg)
    assert event["donor_rel_path"] == "a/fr_200.html"
    assert event["entity_sha256"] == digest_bytes(fr_body)
    assert event["entity_sha256"] != digest_bytes(de_body)


@pytest.mark.parametrize("body,ct_200,ct_304,needle", [
    (b"\x80\x81\x82", "text/html; charset=windows-1252",
     "text/html; charset=utf-8", "严格解码"),
    (b"\xef\xbb\xbfok", "text/plain; charset=utf-8",
     "text/plain; charset=utf-16le", "BOM")])
def test_incompatible_refreshed_charset_is_refused_with_evidence(
        capture_tree, make_config, body, ct_200, ct_304, needle):
    suffix = ".txt" if "plain" in ct_200 else ".html"
    files = {f"a/doc_200{suffix}": body, f"b/doc_304{suffix}": b""}
    sidecars = {
        "a/doc_200": state_200(T_200, FR, ETAG_V1, ct_200),
        "b/doc_304": state_304(T_304, FR, ETAG_V1, {"Content-Type": ct_304})}
    cfg = run_tree(make_config, capture_tree, files, sidecars)
    event = event_for(f"b/doc_304{suffix}", cfg)
    assert event["status"] == "attributed"
    contract = views(event)
    refreshed = contract["refreshed_view"]
    assert refreshed["published"] is False and refreshed["success"] is False
    assert refreshed["rejection"]["code"] == "E_304_REFRESHED_UNDECODABLE"
    assert needle in refreshed["rejection"]["message"]
    assert contract["forensic_original"]["published"] is True
    assert not (cfg.transcode_dir / refreshed["view_rel_path"]).exists()
    assert event["synthesized_headers"]
    assert "E_304_REFRESHED_UNDECODABLE" in event["error_codes"]


def test_synthesize_headers_overrides_only_present_fields():
    old = {"Content-Type": "text/html; charset=windows-1252",
           "X-Keep": "same", "Content-Length": "42"}
    new = {"content-type": "text/html; charset=utf-8", "X-Added": "1"}
    by_name = {r["name"].lower(): r for r in synthesize_headers(old, new)}
    assert by_name["content-type"] == {"name": "content-type",
                                       "value": "text/html; charset=utf-8",
                                       "source": "status_304"}
    assert by_name["x-keep"]["value"] == "same"
    assert by_name["x-keep"]["source"] == "status_200"
    assert by_name["content-length"]["source"] == "status_200"
    assert by_name["x-added"]["source"] == "status_304"
