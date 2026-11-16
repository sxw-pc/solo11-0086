"""离线 gzip 解封装：成员验收、两条归档路线、上限、旧样本与确定性。"""

from __future__ import annotations

import json

import yaml

from decodebench.config import load_config
from decodebench.decompress import decompress
from decodebench.pipeline import run
from decodebench.scanner import scan

from gzip_support import BODY_A, BODY_B, build_tree, entry, gz, sha


def test_repository_fixtures_without_gzip_declaration_keep_legacy_flow(make_config):
    config = make_config()
    run(config, "2024-01-01T00:00:00Z")
    manifest = json.loads(config.manifest_path.read_text(encoding="utf-8"))
    assert manifest["summary"]["files_total"] == 10
    for row in manifest["files"]:
        assert row["content_encoding"]["status"] == "none"
        assert row["content_encoding"]["published_body"] is True
        assert row["decoded_sha256"] == row["source_sha256"]
        assert row["entity_sha256"] == row["source_sha256"]
        assert row["transcode"]["partial"] is False


def test_valid_multi_member_is_complete_and_published_once(make_config, tmp_path):
    first, second = gz(BODY_A), gz(BODY_B)
    responses = build_tree(
        tmp_path,
        {"multi.html": first + second},
        {"multi.html": {"Content-Type": "text/html", "Content-Encoding": "gzip"}},
    )
    config = make_config(scan_root=responses, sidecar_root=tmp_path / "sidecars")
    result = run(config, "2024-01-01T00:00:00Z")
    manifest = json.loads(config.manifest_path.read_text(encoding="utf-8"))
    row = entry(manifest, "multi.html")

    assert row["content_encoding"]["status"] == "complete"
    assert row["content_encoding"]["verified_members"] == 2
    assert [member["status"] for member in row["content_encoding"]["members"]] == [
        "verified",
        "verified",
    ]
    assert row["entity_sha256"] == sha(first + second)
    assert row["decoded_sha256"] == sha(BODY_A + BODY_B)
    assert row["transcode"]["success"] is True
    assert row["transcode"]["partial"] is False
    assert row["transcode"]["output_rel_path"] == "multi.html"
    assert row["decision"]["encoding"] == "utf-8"
    assert row["warnings"] == []
    output = (config.transcode_dir / "multi.html").read_bytes()
    assert "第一段正文" in output.decode("utf-8")
    assert "第二段正文" in output.decode("utf-8")
    # 原实体与正文摘要都出现在报告中。
    report = json.loads((config.reports_dir / "report.json").read_text(encoding="utf-8"))
    reported = next(item for item in report["files"] if item["rel_path"] == "multi.html")
    assert reported["entity_sha256"] == sha(first + second)
    assert reported["decoded_sha256"] == sha(BODY_A + BODY_B)


def test_second_member_crc_error_strict_keeps_no_body(make_config, tmp_path):
    first, second = gz(BODY_A), bytearray(gz(BODY_B))
    second[-8] ^= 0xFF
    responses = build_tree(
        tmp_path,
        {"broken.html": gz(BODY_A) + bytes(second)},
        {"broken.html": {"Content-Encoding": "gzip"}},
    )
    config = make_config(scan_root=responses, sidecar_root=tmp_path / "sidecars")
    run(config, "2024-01-01T00:00:00Z")
    manifest = json.loads(config.manifest_path.read_text(encoding="utf-8"))
    row = entry(manifest, "broken.html")

    enc = row["content_encoding"]
    assert enc["status"] == "strict_failed"
    assert enc["verified_members"] == 1
    assert enc["published_body"] is False
    assert enc["failure"]["code"] == "E_GZIP_CRC_MISMATCH"
    assert enc["failure"]["member_index"] == 1
    assert row["decoded_sha256"] is None
    assert row["transcode"]["success"] is False
    assert row["transcode"]["partial"] is False
    assert row["transcode"]["output_rel_path"] is None
    assert row["decision"]["method"] == "unresolved"
    assert row["decision"]["encoding"] == ""
    assert not (config.transcode_dir / "broken.html").exists()
    assert not (config.partial_dir / "broken.html.partial.utf8").exists()
    # 失败 member 的字节不会出现在任何输出中。
    assert not any(
        BODY_B[:8] in path.read_bytes()
        for path in config.transcode_dir.rglob("*")
        if path.is_file()
    )
    assert sha(gz(BODY_A) + bytes(second)) == enc["entity_sha256"]


def test_second_member_truncation_is_failure(make_config, tmp_path):
    first, second = gz(BODY_A), gz(BODY_B)
    truncated = first + second[: len(second) - 6]
    responses = build_tree(
        tmp_path,
        {"truncated.html": truncated},
        {"truncated.html": {"Content-Encoding": "gzip"}},
    )
    config = make_config(scan_root=responses, sidecar_root=tmp_path / "sidecars")
    run(config, "2024-01-01T00:00:00Z")
    manifest = json.loads(config.manifest_path.read_text(encoding="utf-8"))
    row = entry(manifest, "truncated.html")
    assert row["content_encoding"]["status"] == "strict_failed"
    assert row["content_encoding"]["failure"]["member_index"] == 1
    assert row["content_encoding"]["published_body"] is False
    assert row["transcode"]["success"] is False
    assert not (config.transcode_dir / "truncated.html").exists()


def test_verified_prefix_route_publishes_only_intact_prefix(make_config, tmp_path):
    first = gz(BODY_A)
    broken = bytearray(gz(BODY_B))
    broken[-8] ^= 0xFF
    responses = build_tree(
        tmp_path,
        {"prefix.html": first + bytes(broken)},
        {"prefix.html": {"Content-Type": "text/html", "Content-Encoding": "gzip"}},
    )
    config = make_config(
        scan_root=responses,
        sidecar_root=tmp_path / "sidecars",
        content_encoding={"failure_route": "verified_prefix"},
    )
    result = run(config, "2024-01-01T00:00:00Z")
    manifest = json.loads(config.manifest_path.read_text(encoding="utf-8"))
    row = entry(manifest, "prefix.html")

    assert row["content_encoding"]["status"] == "verified_prefix"
    assert row["content_encoding"]["partial_prefix"] is True
    assert row["content_encoding"]["published_body"] is False
    assert row["content_encoding"]["decoded_sha256"] == sha(BODY_A)
    assert row["decoded_sha256"] == sha(BODY_A)
    assert row["transcode"]["partial"] is True
    assert row["transcode"]["success"] is False
    assert row["transcode"]["output_rel_path"] == "prefix.html.partial.utf8"
    partial = config.partial_dir / "prefix.html.partial.utf8"
    assert partial.is_file()
    text = partial.read_text(encoding="utf-8")
    assert "第一段正文" in text
    assert "第二段正文" not in text
    assert row["transcode"]["output_sha256"] == sha(partial.read_bytes())
    # partial 产物不进入成功计数。
    assert result["summary"]["transcode_success"] == 0
    assert result["summary"]["transcode_partial"] == 1
    assert not (config.transcode_dir / "prefix.html").exists()
    assert "W_GZIP_PARTIAL_PREFIX" in {w["code"] for w in row["warnings"]}


def test_charset_evidence_comes_only_from_verified_body(make_config, tmp_path):
    text = (
        '<?xml version="1.0" encoding="UTF-16"?>\n'
        "<record><title>压缩正文内的 UTF-16 样本</title></record>\n"
    )
    body = b"\xff\xfe" + text.encode("utf-16-le")
    responses = build_tree(
        tmp_path,
        {"utf16.html": gz(body)},
        {
            "utf16.html": {
                "Content-Type": "application/xml; charset=utf-16le",
                "Content-Encoding": "gzip",
            }
        },
    )
    config = make_config(scan_root=responses, sidecar_root=tmp_path / "sidecars")
    run(config, "2024-01-01T00:00:00Z")
    manifest = json.loads(config.manifest_path.read_text(encoding="utf-8"))
    row = entry(manifest, "utf16.html")

    # 实体以 gzip magic 开头，没有 BOM；BOM/声明只能来自解封装后的正文。
    assert row["content_encoding"]["status"] == "complete"
    assert row["bom"]["encoding"] == "utf-16-le"
    assert row["entity_sha256"] == sha(gz(body))
    assert row["decoded_sha256"] == sha(body)
    assert row["entity_sha256"] != row["decoded_sha256"]
    assert row["decoded_sha256"] != row["source_sha256"]
    assert row["decision"]["encoding"] == "utf-16-le"
    assert row["decision"]["method"] == "bom"
    declaration = next(
        item for item in row["evidence"] if item["source"] == "xml_declaration"
    )
    assert declaration["offset"] == body.find("UTF-16".encode("utf-16-le"))
    content = next(
        item for item in row["evidence"] if item["source"] == "content_encoding"
    )
    assert content["matches_decision"] is None
    output = (config.transcode_dir / "utf16.html").read_bytes()
    assert output.startswith(b'<?xml version="1.0" encoding="utf-8"?>')
    assert "压缩正文内的 UTF-16 样本" in output.decode("utf-8")


def test_disabled_or_untrusted_sidecar_keeps_legacy_byte_flow(make_config, tmp_path):
    entity = gz(BODY_A)
    responses = build_tree(
        tmp_path,
        {"gated.html": entity},
        {"gated.html": {"Content-Encoding": "gzip"}},
    )
    for extra in ({"enabled": False},):
        config = make_config(
            scan_root=responses,
            sidecar_root=tmp_path / "sidecars",
            content_encoding=extra,
        )
        run(config, "2024-01-01T00:00:00Z")
        manifest = json.loads(config.manifest_path.read_text(encoding="utf-8"))
        row = entry(manifest, "gated.html")
        assert row["content_encoding"]["status"] == "none"
        assert row["entity_sha256"] == sha(entity)
        assert row["decoded_sha256"] == sha(entity)
        # 未启用解封装时仍按原字节严格解码；gzip 字节不是合法 UTF-8。
        assert row["decision"]["encoding"] != "utf-8"
        assert row["transcode"]["partial"] is False

    untrusted = make_config(
        scan_root=responses, sidecar_root=tmp_path / "sidecars", out_dir=tmp_path / "u"
    )
    data = yaml.safe_load(untrusted.config_path.read_text(encoding="utf-8"))
    data["detection"]["trusted_http_headers"] = False
    untrusted.config_path.write_text(
        yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    reloaded = load_config(untrusted.config_path)
    run(reloaded, "2024-01-01T00:00:00Z")
    manifest = json.loads(reloaded.manifest_path.read_text(encoding="utf-8"))
    row = entry(manifest, "gated.html")
    assert row["content_encoding"]["status"] == "none"
    assert row["decoded_sha256"] == sha(entity)


def test_prefix_reruns_are_deterministic_and_clear_stale_full_output(make_config, tmp_path):
    first = gz(BODY_A)
    broken = bytearray(gz(BODY_B))
    broken[-8] ^= 0xFF
    responses = build_tree(
        tmp_path,
        {"rerun.html": first + bytes(broken)},
        {"rerun.html": {"Content-Type": "text/html", "Content-Encoding": "gzip"}},
    )
    config = make_config(
        scan_root=responses,
        sidecar_root=tmp_path / "sidecars",
        content_encoding={"failure_route": "verified_prefix"},
    )
    (config.transcode_dir / "rerun.html").parent.mkdir(parents=True, exist_ok=True)
    (config.transcode_dir / "rerun.html").write_bytes(b"stale success\n")

    run(config, "2024-01-01T00:00:00Z")
    manifest_path = config.manifest_path
    first_hash = sha(manifest_path.read_bytes())
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    row = entry(manifest, "rerun.html")
    assert row["transcode"]["success"] is False
    assert row["transcode"]["partial"] is True
    assert not (config.transcode_dir / "rerun.html").exists()
    partial_path = config.partial_dir / "rerun.html.partial.utf8"
    first_partial = sha(partial_path.read_bytes())

    second = run(config, "2024-01-01T00:00:00Z")
    assert sha(manifest_path.read_bytes()) == first_hash
    assert second["summary"]["transcode_success"] == 0
    assert second["summary"]["transcode_partial"] == 1
    assert sha(partial_path.read_bytes()) == first_partial
    assert json.loads(manifest_path.read_text(encoding="utf-8")) == manifest
