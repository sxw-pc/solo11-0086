from __future__ import annotations

import hashlib

from decodebench.pipeline import run


def _entity(manifest: dict, entity_id: str = "e1") -> dict:
    return next(
        item for item in manifest["assembly"]["entities"] if item["entity_id"] == entity_id
    )


def _fragment(manifest: dict, rel_path: str) -> dict:
    return next(
        item for item in manifest["assembly"]["fragments"] if item["rel_path"] == rel_path
    )


def _decl(
    entity_id: str,
    capture_id: str,
    start: int,
    end: int,
    size: int = 4,
    validator: str = "sha256:v1",
) -> dict:
    return {
        "entity_id": entity_id,
        "capture_id": capture_id,
        "byte_start": start,
        "byte_end_inclusive": end,
        "entity_size": size,
        "validator": validator,
    }


def _conflict_entity(fragment_dir):
    fragment_dir("blue-0.bin", b"A\xc3", _decl("e1", "capture-blue", 0, 1))
    fragment_dir("blue-1.bin", b"\xa9B", _decl("e1", "capture-blue", 2, 3))
    fragment_dir("red-0.bin", b"A\xc3", _decl("e1", "capture-red", 0, 1))
    fragment_dir("red-1.bin", b"\xaaB", _decl("e1", "capture-red", 2, 3))


def test_consensus_rejects_two_complete_conflicting_captures(
    fragment_dir, assemble_config, manifest_reader, now
):
    _conflict_entity(fragment_dir)
    config = assemble_config(fragment_dir.responses, fragment_dir.sidecars, contract="consensus")
    run(config, now)
    manifest = manifest_reader(config)
    entity = _entity(manifest)

    assert entity["status"] == "ambiguous"
    assert entity["complete"] is False
    assert entity["assembled_sha256"] is None
    assert entity["selected"] is None
    assert len(entity["groups"]) == 2
    assert {group["status"] for group in entity["groups"]} == {"complete"}
    assert {group["capture_id"] for group in entity["groups"]} == {
        "capture-blue",
        "capture-red",
    }
    assert len(entity["excluded"]) == 2
    assert {row["capture_id"] for row in entity["excluded"]} == {
        "capture-blue",
        "capture-red",
    }
    assert entity["conflict"]["byte_offset"] == 2
    assert {entity["conflict"]["left"]["byte"], entity["conflict"]["right"]["byte"]} == {
        "a9",
        "aa",
    }
    # 两个被排除组合都保留了覆盖区间与首个冲突字节，不靠扫描顺序挑选。
    for row in entity["excluded"]:
        assert row["coverage"] == [[0, 1], [2, 3]]
        assert row["first_conflict"]["byte_offset"] == 2

    # 不发布正式 UTF-8：实体输出目录为空。
    output = config.transcode_dir / "_assembled"
    assert not output.exists() or not any(output.rglob("*"))
    # 片段自身也不被当成普通文件转码。
    assert manifest["files"] == []
    assert manifest["summary"]["transcode_success"] == 0


def test_authorized_capture_selects_blue_and_records_excluded_conflict(
    fragment_dir, assemble_config, manifest_reader, now
):
    _conflict_entity(fragment_dir)
    config = assemble_config(
        fragment_dir.responses,
        fragment_dir.sidecars,
        contract="authorized_capture",
        priority=["capture-blue"],
    )
    run(config, now)
    manifest = manifest_reader(config)
    entity = _entity(manifest)

    assert entity["status"] == "complete"
    assert entity["complete"] is True
    assert entity["capture_id"] == "capture-blue"
    expected = hashlib.sha256(b"A\xc3\xa9B").hexdigest()
    assert entity["assembled_sha256"] == expected
    assert entity["transcode"]["success"] is True
    assert entity["transcode"]["output_sha256"] == hashlib.sha256(b"A\xc3\xa9B").hexdigest()
    output = config.transcode_dir / entity["transcode"]["output_rel_path"]
    assert output.read_bytes() == b"A\xc3\xa9B"

    excluded = entity["excluded"]
    assert len(excluded) == 1
    assert excluded[0]["capture_id"] == "capture-red"
    assert excluded[0]["sha256"] == hashlib.sha256(b"A\xc3\xaaB").hexdigest()
    assert excluded[0]["first_conflict"]["byte_offset"] == 2
    assert excluded[0]["first_conflict"]["excluded"]["byte"] == "aa"
    assert excluded[0]["first_conflict"]["selected"]["byte"] == "a9"
    assert manifest["assembly"]["summary"]["entities_transcoded"] == 1


def test_each_fragment_and_summary_is_retained(
    fragment_dir, assemble_config, manifest_reader, now
):
    _conflict_entity(fragment_dir)
    config = assemble_config(
        fragment_dir.responses,
        fragment_dir.sidecars,
        contract="authorized_capture",
        priority=["capture-blue"],
    )
    run(config, now)
    manifest = manifest_reader(config)
    fragments = manifest["assembly"]["fragments"]
    assert [item["rel_path"] for item in fragments] == [
        "blue-0.bin",
        "blue-1.bin",
        "red-0.bin",
        "red-1.bin",
    ]
    for item in fragments:
        source = (fragment_dir.responses / item["rel_path"]).read_bytes()
        assert item["source_sha256"] == hashlib.sha256(source).hexdigest()
        assert item["sha256"] == hashlib.sha256(source).hexdigest()
        assert item["status"] == "ok"
    by_name = {item["rel_path"]: item for item in fragments}
    assert by_name["blue-0.bin"]["consumed"] is True
    assert by_name["blue-1.bin"]["consumed"] is True
    # 另一组合的片段保留但未混入输出。
    assert by_name["red-0.bin"]["consumed"] is False
    assert by_name["red-1.bin"]["consumed"] is False
    assert [item["byte_start"] for item in fragments] == [0, 2, 0, 2]
    assert all(item["entity_size"] == 4 for item in fragments)


def test_conflicting_entity_keeps_each_group_coverage(
    fragment_dir, assemble_config, manifest_reader, now
):
    _conflict_entity(fragment_dir)
    config = assemble_config(fragment_dir.responses, fragment_dir.sidecars)
    run(config, now)
    manifest = manifest_reader(config)
    entity = _entity(manifest)
    groups = {group["capture_id"]: group for group in entity["groups"]}
    blue = groups["capture-blue"]["combinations"][0]
    red = groups["capture-red"]["combinations"][0]
    assert blue["sha256"] == hashlib.sha256(b"A\xc3\xa9B").hexdigest()
    assert red["sha256"] == hashlib.sha256(b"A\xc3\xaaB").hexdigest()
    assert {item["rel_path"] for item in blue["fragments"]} == {"blue-0.bin", "blue-1.bin"}
    assert {item["rel_path"] for item in red["fragments"]} == {"red-0.bin", "red-1.bin"}
    excluded = {row["sha256"]: row for row in entity["excluded"]}
    assert excluded[blue["sha256"]]["coverage"] == [[0, 1], [2, 3]]
    assert excluded[red["sha256"]]["coverage"] == [[0, 1], [2, 3]]


def test_cjk_multibyte_split_is_assembled_before_decoding(
    fragment_dir, assemble_config, manifest_reader, now
):
    text = '<html><meta charset="utf-8"><p>分段中文，跨片段边界。</p></html>'
    raw = text.encode("utf-8")
    marker = "分".encode("utf-8")
    split = raw.index(marker) + 1  # 断在一个三字节字符中间
    fragment_dir(
        "part-0.html", raw[:split], _decl("resp-1", "cap-a", 0, split - 1, len(raw))
    )
    fragment_dir(
        "part-1.html",
        raw[split:],
        _decl("resp-1", "cap-a", split, len(raw) - 1, len(raw)),
    )
    config = assemble_config(
        fragment_dir.responses,
        fragment_dir.sidecars,
        extensions=[".html"],
    )
    run(config, now)
    manifest = manifest_reader(config)
    entity = _entity(manifest, "resp-1")

    assert entity["status"] == "complete"
    assert entity["assembled_sha256"] == hashlib.sha256(raw).hexdigest()
    assert entity["transcode"]["success"] is True
    encoded = (config.transcode_dir / entity["transcode"]["output_rel_path"]).read_bytes()
    assert encoded == raw
    assert entity["decision"]["encoding"] == "utf-8"
    assert entity["decision"]["method"] == "meta_charset"
    codes = {item["code"] for item in entity["warnings"]}
    assert "E_DECLARATION_UNDECODABLE" not in codes
    assert "E_UNDECODABLE" not in codes
    # 片段单独看会截断多字节字符，但不会被单独报编码失败。
    assert all(_fragment(manifest, item["rel_path"])["consumed"] for item in entity["fragments"])


def test_consistent_overlap_is_accepted_and_gap_blocks_completion(
    fragment_dir, assemble_config, manifest_reader, now
):
    fragment_dir("a.bin", b"A\xc3", _decl("e1", "cap", 0, 1))
    fragment_dir("b.bin", b"\xc3\xa9", _decl("e1", "cap", 1, 2))
    fragment_dir("c.bin", b"\xa9B", _decl("e1", "cap", 2, 3))
    config = assemble_config(fragment_dir.responses, fragment_dir.sidecars)
    run(config, now)
    entity = _entity(manifest_reader(config))
    assert entity["status"] == "complete"
    assert entity["assembled_sha256"] == hashlib.sha256(b"A\xc3\xa9B").hexdigest()

    # 另建一个缺 2..3 的实体：0..1 覆盖，2..3 无片段。
    fragment_dir("gap-0.bin", b"A\xc3", _decl("e2", "cap", 0, 1))
    run(config, now)
    gap = _entity(manifest_reader(config), "e2")
    assert gap["status"] == "incomplete"
    assert gap["complete"] is False
    assert any("2..3" in reason for reason in gap["groups"][0]["reasons"])


def test_consensus_archives_when_all_complete_combinations_agree(
    fragment_dir, assemble_config, manifest_reader, now
):
    payload = b"A\xc3\xa9B"
    fragment_dir("blue-0.bin", payload[:2], _decl("e1", "capture-blue", 0, 1))
    fragment_dir("blue-1.bin", payload[2:], _decl("e1", "capture-blue", 2, 3))
    fragment_dir("red-0.bin", payload[:2], _decl("e1", "capture-red", 0, 1))
    fragment_dir("red-1.bin", payload[2:], _decl("e1", "capture-red", 2, 3))
    config = assemble_config(fragment_dir.responses, fragment_dir.sidecars)
    run(config, now)
    entity = _entity(manifest_reader(config))
    assert entity["status"] == "complete"
    assert entity["assembled_sha256"] == hashlib.sha256(payload).hexdigest()
    assert entity["capture_id"] in {"capture-blue", "capture-red"}
    assert entity["excluded"] == []
    output = config.transcode_dir / entity["transcode"]["output_rel_path"]
    assert output.read_bytes() == payload


def test_bom_on_assembled_bytes_is_interpreted_only_after_assembly(
    fragment_dir, assemble_config, manifest_reader, now
):
    raw = b"\xef\xbb\xbf" + '<meta charset="utf-8">中文'.encode("utf-8")
    split = raw.index("中".encode("utf-8")) + 1
    fragment_dir("p0.html", raw[:split], _decl("e1", "cap", 0, split - 1, len(raw)))
    fragment_dir("p1.html", raw[split:], _decl("e1", "cap", split, len(raw) - 1, len(raw)))
    config = assemble_config(
        fragment_dir.responses, fragment_dir.sidecars, extensions=[".html"]
    )
    run(config, now)
    entity = _entity(manifest_reader(config))
    assert entity["status"] == "complete"
    bom = entity["bom"]
    assert bom is not None and bom["encoding"] == "utf-8"
    assert entity["decision"]["method"] == "bom"
    assert (config.transcode_dir / entity["transcode"]["output_rel_path"]).read_bytes() == raw[3:]
