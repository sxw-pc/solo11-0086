"""离线 gzip 解封装：字节/膨胀上限、别名与不可用声明。"""

from __future__ import annotations

import json
import zlib

import pytest

from decodebench.decompress import decompress
from decodebench.pipeline import run
from decodebench.scanner import scan

from gzip_support import (
    BODY_A, BODY_B, build_tree, corrupt_second_member, entry, gz, sha,
)


def test_expansion_limits_stop_with_stable_diagnostic(make_config, tmp_path):
    bomb = gz(b"A" * 200_000)
    responses = build_tree(
        tmp_path,
        {"bomb.html": bomb},
        {"bomb.html": {"Content-Encoding": "gzip"}},
    )
    config = make_config(
        scan_root=responses,
        sidecar_root=tmp_path / "sidecars",
        content_encoding={"inflate_max_bytes": 4096, "max_expansion_ratio": 1000.0},
    )
    run(config, "2024-01-01T00:00:00Z")
    manifest = json.loads(config.manifest_path.read_text(encoding="utf-8"))
    row = entry(manifest, "bomb.html")
    assert row["content_encoding"]["status"] == "strict_failed"
    assert row["content_encoding"]["failure"]["code"] == "E_GZIP_INFLATE_LIMIT"
    assert row["content_encoding"]["published_body"] is False
    assert row["content_encoding"]["decoded_size"] == 0
    assert "E_GZIP_EXPANSION_LIMIT" in {w["code"] for w in row["warnings"]}
    assert not (config.transcode_dir / "bomb.html").exists()


def test_ratio_limit_is_enforced_separately(make_config, tmp_path):
    responses = build_tree(
        tmp_path,
        {"ratio.html": gz(b"B" * 50_000)},
        {"ratio.html": {"Content-Encoding": "gzip"}},
    )
    config = make_config(
        scan_root=responses,
        sidecar_root=tmp_path / "sidecars",
        content_encoding={"inflate_max_bytes": 10_000_000, "max_expansion_ratio": 2.0},
    )
    source = scan(config)[0]
    result = decompress(source, source.path.read_bytes(), config)
    assert result.failure is not None
    assert result.failure["code"] == "E_GZIP_RATIO_LIMIT"
    assert result.verified_members == 0


def test_entity_limit_is_checked_before_reading(make_config, tmp_path):
    responses = build_tree(
        tmp_path,
        {"big.html": gz(b"C" * 10_000)},
        {"big.html": {"Content-Encoding": "gzip"}},
    )
    config = make_config(
        scan_root=responses,
        sidecar_root=tmp_path / "sidecars",
        content_encoding={"entity_max_bytes": 32},
    )
    run(config, "2024-01-01T00:00:00Z")
    manifest = json.loads(config.manifest_path.read_text(encoding="utf-8"))
    row = entry(manifest, "big.html")
    assert row["content_encoding"]["status"] == "strict_failed"
    assert row["content_encoding"]["failure"]["code"] == "E_GZIP_ENTITY_LIMIT"
    assert row["content_encoding"]["members"] == []
    assert "未载入实体进行解压" in row["content_encoding"]["failure"]["message"]


def test_sidecar_lies_about_gzip_and_old_sample_stays_unchanged(make_config, tmp_path):
    plain = b"<html><head><meta charset=\"utf-8\"></head><body>plain bytes</body></html>"
    legacy = b"<html><head><title>\xe4\xb8\xad\xe6\x96\x87</title></head></html>"
    responses = build_tree(
        tmp_path,
        {"lies.html": plain, "legacy.html": legacy},
        {
            "lies.html": {"Content-Encoding": "gzip"},
            "legacy.html": {"Content-Type": "text/html; charset=utf-8"},
        },
    )
    config = make_config(scan_root=responses, sidecar_root=tmp_path / "sidecars")
    run(config, "2024-01-01T00:00:00Z")
    manifest = json.loads(config.manifest_path.read_text(encoding="utf-8"))

    lying = entry(manifest, "lies.html")
    assert lying["content_encoding"]["status"] == "strict_failed"
    assert lying["content_encoding"]["failure"]["code"] == "E_GZIP_NOT_GZIP"
    assert lying["content_encoding"]["published_body"] is False
    assert lying["decision"]["method"] == "unresolved"
    assert lying["decision"]["encoding"] == ""
    assert lying["entity_sha256"] == sha(plain)
    assert lying["decoded_sha256"] is None
    assert not (config.transcode_dir / "lies.html").exists()

    old = entry(manifest, "legacy.html")
    assert old["content_encoding"]["status"] == "none"
    assert old["decoded_sha256"] == sha(legacy)
    assert old["entity_sha256"] == sha(legacy)
    assert old["transcode"]["success"] is True
    assert old["decision"]["encoding"] == "utf-8"
    assert old["decision"]["method"] == "http_header"
    assert (config.transcode_dir / "legacy.html").read_bytes() == legacy


def test_reruns_are_deterministic_and_stale_outputs_never_count(make_config, tmp_path):
    entity = corrupt_second_member(gz(BODY_A), BODY_B)
    responses = build_tree(
        tmp_path,
        {"rerun.html": entity},
        {"rerun.html": {"Content-Type": "text/html", "Content-Encoding": "gzip"}},
    )
    config = make_config(scan_root=responses, sidecar_root=tmp_path / "sidecars")
    # 先手工放一个“上次成功”的旧产物。
    (config.transcode_dir / "rerun.html").parent.mkdir(parents=True, exist_ok=True)
    (config.transcode_dir / "rerun.html").write_bytes(b"stale success\n")

    run(config, "2024-01-01T00:00:00Z")
    manifest_path = config.manifest_path
    first_hash = sha(manifest_path.read_bytes())
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    row = entry(manifest, "rerun.html")
    assert row["transcode"]["success"] is False
    assert not (config.transcode_dir / "rerun.html").exists()

    second_result = run(config, "2024-01-01T00:00:00Z")
    assert sha(manifest_path.read_bytes()) == first_hash
    assert second_result["summary"]["transcode_success"] == 0
    assert not (config.transcode_dir / "rerun.html").exists()
    assert json.loads(manifest_path.read_text(encoding="utf-8")) == manifest


def test_strict_route_never_publishes_prefix(make_config, tmp_path):
    entity = corrupt_second_member(gz(BODY_A), BODY_B)
    responses = build_tree(
        tmp_path,
        {"strict.html": entity},
        {"strict.html": {"Content-Encoding": "gzip"}},
    )
    config = make_config(
        scan_root=responses,
        sidecar_root=tmp_path / "sidecars",
        content_encoding={"failure_route": "strict"},
    )
    run(config, "2024-01-01T00:00:00Z")
    manifest = json.loads(config.manifest_path.read_text(encoding="utf-8"))
    row = entry(manifest, "strict.html")
    assert row["content_encoding"]["status"] == "strict_failed"
    assert row["content_encoding"]["verified_members"] == 1
    assert row["content_encoding"]["partial_prefix"] is False
    assert row["decoded_sha256"] is None
    assert not (config.partial_dir / "strict.html.partial.utf8").exists()


def test_member_boundary_garbage_is_rejected(make_config, tmp_path):
    responses = build_tree(
        tmp_path,
        {"boundary.html": gz(BODY_A) + b"not-a-member"},
        {"boundary.html": {"Content-Encoding": "gzip"}},
    )
    config = make_config(scan_root=responses, sidecar_root=tmp_path / "sidecars")
    source = scan(config)[0]
    result = decompress(source, source.path.read_bytes(), config)
    assert result.failure is not None
    assert result.failure["code"] == "E_GZIP_MEMBER_BOUNDARY"
    assert result.failure["member_index"] == 1
    assert result.verified_members == 1
    assert result.published_body is False


@pytest.mark.parametrize("encoding", ["gzip", "x-gzip", "GZip"])
def test_content_encoding_alias_is_accepted(encoding, make_config, tmp_path):
    responses = build_tree(
        tmp_path,
        {"alias.html": gz(BODY_A)},
        {"alias.html": {"Content-Encoding": encoding}},
    )
    config = make_config(scan_root=responses, sidecar_root=tmp_path / "sidecars")
    run(config, "2024-01-01T00:00:00Z")
    manifest = json.loads(config.manifest_path.read_text(encoding="utf-8"))
    row = entry(manifest, "alias.html")
    assert row["content_encoding"]["status"] == "complete"
    assert row["transcode"]["success"] is True


def test_member_header_invalid_and_header_crc_rejected(make_config, tmp_path):
    valid = gz(BODY_A)
    bad_method = bytearray(valid)
    bad_method[2] = 7
    reserved = bytearray(valid)
    reserved[3] |= 0x20
    responses = build_tree(
        tmp_path,
        {"method.html": bytes(bad_method), "reserved.html": bytes(reserved)},
        {
            "method.html": {"Content-Encoding": "gzip"},
            "reserved.html": {"Content-Encoding": "gzip"},
        },
    )
    config = make_config(scan_root=responses, sidecar_root=tmp_path / "sidecars")
    run(config, "2024-01-01T00:00:00Z")
    manifest = json.loads(config.manifest_path.read_text(encoding="utf-8"))
    for name in ("method.html", "reserved.html"):
        row = entry(manifest, name)
        assert row["content_encoding"]["failure"]["code"] == "E_GZIP_HEADER_INVALID"
        assert row["content_encoding"]["published_body"] is False
        assert row["transcode"]["output_rel_path"] is None


def test_fhcrc_is_validated_and_member_count_is_capped(make_config, tmp_path):
    base = gz(b"one")
    header = bytearray(base[:10])
    header[3] |= 0x02
    header_crc = zlib.crc32(bytes(header)) & 0xFFFF
    framed = bytes(header) + bytes([header_crc & 0xFF, header_crc >> 8]) + base[10:]
    responses = build_tree(
        tmp_path,
        {"fhcrc.html": framed, "many.html": gz(b"a") + gz(b"b") + gz(b"c")},
        {
            "fhcrc.html": {"Content-Encoding": "gzip"},
            "many.html": {"Content-Encoding": "gzip"},
        },
    )
    ok_config = make_config(scan_root=responses, sidecar_root=tmp_path / "sidecars")
    run(ok_config, "2024-01-01T00:00:00Z")
    manifest = json.loads(ok_config.manifest_path.read_text(encoding="utf-8"))
    assert entry(manifest, "fhcrc.html")["content_encoding"]["status"] == "complete"

    capped = make_config(
        scan_root=responses,
        sidecar_root=tmp_path / "sidecars",
        content_encoding={"max_members": 2},
        out_dir=tmp_path / "out2",
    )
    run(capped, "2024-01-01T00:00:00Z")
    other = json.loads(capped.manifest_path.read_text(encoding="utf-8"))
    row = entry(other, "many.html")
    assert row["content_encoding"]["failure"]["code"] == "E_GZIP_MEMBER_LIMIT"
    assert row["content_encoding"]["verified_members"] == 2


def test_decompress_route_override_is_honoured(make_config, tmp_path):
    entity = corrupt_second_member(gz(BODY_A), BODY_B)
    responses = build_tree(
        tmp_path,
        {"override.html": entity},
        {"override.html": {"Content-Encoding": "gzip"}},
    )
    config = make_config(scan_root=responses, sidecar_root=tmp_path / "sidecars")
    source = scan(config)[0]
    strict = decompress(source, entity, config, route="strict")
    prefix = decompress(source, entity, config, route="verified_prefix")
    assert strict.status == "strict_failed" and strict.body is None
    assert prefix.status == "verified_prefix" and prefix.body == BODY_A
    with pytest.raises(ValueError):
        decompress(source, entity, config, route="archive")


def test_invalid_content_encoding_config_is_rejected(make_config, tmp_path):
    with pytest.raises(Exception) as excinfo:
        make_config(content_encoding={"failure_route": "publish_everything"})
    assert "failure_route" in str(excinfo.value)
    with pytest.raises(Exception) as excinfo:
        make_config(content_encoding={"max_expansion_ratio": 0})
    assert "max_expansion_ratio" in str(excinfo.value)


def test_unsupported_content_encoding_fails_without_guessing(make_config, tmp_path):
    responses = build_tree(
        tmp_path,
        {"brotli.html": BODY_A},
        {"brotli.html": {"Content-Encoding": "br"}},
    )
    config = make_config(scan_root=responses, sidecar_root=tmp_path / "sidecars")
    run(config, "2024-01-01T00:00:00Z")
    manifest = json.loads(config.manifest_path.read_text(encoding="utf-8"))
    row = entry(manifest, "brotli.html")
    assert row["content_encoding"]["failure"]["code"] == "E_CONTENT_ENCODING_INVALID"
    assert row["decision"]["encoding"] == ""
    assert row["transcode"]["success"] is False
