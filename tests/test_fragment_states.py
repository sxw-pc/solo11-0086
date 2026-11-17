from __future__ import annotations

import hashlib

from decodebench.pipeline import run



def _decl(
    entity_id: str = "e1",
    capture_id: str = "cap",
    start: int = 0,
    end: int = 1,
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


def _entity(manifest: dict, entity_id: str = "e1") -> dict:
    return next(
        item for item in manifest["assembly"]["entities"] if item["entity_id"] == entity_id
    )


def test_duplicate_interval_same_content_yields_one_combination(
    fragment_dir, assemble_config, manifest_reader, now
):
    fragment_dir("a.bin", b"A\xc3\xa9B", _decl("e1", "cap", 0, 3))
    fragment_dir("b.bin", b"A\xc3\xa9B", _decl("e1", "cap", 0, 3))
    config = assemble_config(fragment_dir.responses, fragment_dir.sidecars)
    run(config, now)
    entity = _entity(manifest_reader(config))
    assert entity["status"] == "complete"
    # 两条覆盖路径产生完全相同的实体字节，只发布一种实体。
    combinations = entity["groups"][0]["combinations"]
    assert len({item["sha256"] for item in combinations}) == 1
    assert len(combinations) == 2
    assert entity["groups"][0]["explored"] == 2
    shared = entity["shared_fragments"]
    assert len(shared) == 1
    assert shared[0]["byte_start"] == 0 and shared[0]["byte_end_inclusive"] == 3
    assert {row["rel_path"] for row in shared[0]["fragments"]} == {"a.bin", "b.bin"}


def test_duplicate_interval_conflicting_content_marks_group_conflict(
    fragment_dir, assemble_config, manifest_reader, now
):
    fragment_dir("a.bin", b"A\xc3\xa9B", _decl("e1", "cap", 0, 3))
    fragment_dir("b.bin", b"A\xc3\xaaB", _decl("e1", "cap", 0, 3))
    config = assemble_config(fragment_dir.responses, fragment_dir.sidecars)
    run(config, now)
    entity = _entity(manifest_reader(config))
    # 两个互斥的整长候选各自都能覆盖全长，consensus 不做单选，报 ambiguous。
    assert entity["status"] == "ambiguous"
    group = entity["groups"][0]
    assert group["status"] == "complete"
    assert group["overlap_conflicts"][0]["byte_offset"] == 2
    assert {item["sha256"] for item in group["combinations"]} == {
        hashlib.sha256(b"A\xc3\xa9B").hexdigest(),
        hashlib.sha256(b"A\xc3\xaaB").hexdigest(),
    }
    assert entity["complete"] is False
    assert entity["conflict"]["byte_offset"] == 2


def test_conflicting_fragments_that_must_be_combined_are_a_group_conflict(
    fragment_dir, assemble_config, manifest_reader, now
):
    # 0..1 与 1..3 必须同选才能覆盖全长，且重叠字节 1 冲突。
    fragment_dir("a.bin", b"A\xc3", _decl("e1", "cap-a", 0, 1))
    fragment_dir("b.bin", b"\xaa\xaaB", _decl("e1", "cap-a", 1, 3))
    config = assemble_config(fragment_dir.responses, fragment_dir.sidecars)
    run(config, now)
    entity = _entity(manifest_reader(config))
    group = entity["groups"][0]
    assert group["status"] == "conflict"
    assert group["combinations"] == []
    assert group["overlap_conflicts"][0]["byte_offset"] == 1
    assert entity["complete"] is False


def test_out_of_bounds_and_length_mismatch_are_stable_states(
    fragment_dir, assemble_config, manifest_reader, now
):
    fragment_dir("tail.bin", b"\xa9B", _decl("e1", "cap", 2, 4, size=4))
    fragment_dir("head.bin", b"A\xc3", _decl("e1", "cap", -1, 0, size=4))
    fragment_dir("short.bin", b"A\xc3", _decl("e1", "cap", 0, 3, size=4))
    config = assemble_config(fragment_dir.responses, fragment_dir.sidecars)
    run(config, now)
    manifest = manifest_reader(config)
    states = {item["rel_path"]: item["status"] for item in manifest["assembly"]["fragments"]}
    assert states["tail.bin"] == "out_of_bounds"
    assert states["head.bin"] == "out_of_bounds"
    assert states["short.bin"] == "prefix_only"
    entity = _entity(manifest)
    assert entity["complete"] is False


def test_conflicting_entity_size_and_validator_block_assembly(
    fragment_dir, assemble_config, manifest_reader, now
):
    fragment_dir("a.bin", b"A\xc3", _decl("e1", "cap", 0, 1, size=4, validator="v1"))
    fragment_dir("b.bin", b"\xa9B", _decl("e1", "cap", 2, 3, size=5, validator="v2"))
    config = assemble_config(fragment_dir.responses, fragment_dir.sidecars)
    run(config, now)
    entity = _entity(manifest_reader(config))
    assert entity["status"] == "identity_mismatch"
    assert entity["complete"] is False
    assert any("entity_size" in reason for reason in entity["reasons"])


def test_conflicting_validator_inside_one_capture_blocks_group(
    fragment_dir, assemble_config, manifest_reader, now
):
    fragment_dir("a.bin", b"A\xc3", _decl("e1", "cap", 0, 1, validator="v1"))
    fragment_dir("b.bin", b"\xa9B", _decl("e1", "cap", 2, 3, validator="v2"))
    config = assemble_config(fragment_dir.responses, fragment_dir.sidecars)
    run(config, now)
    entity = _entity(manifest_reader(config))
    assert entity["status"] == "incomplete"
    assert entity["complete"] is False
    assert entity["groups"][0]["status"] == "validator_mismatch"
    assert any("validator" in reason for reason in entity["groups"][0]["reasons"])


def test_source_rewritten_after_scan_is_rejected(
    fragment_dir, assemble_config, manifest_reader, now
):
    from decodebench.fragments import load_fragment
    from decodebench.scanner import scan

    path = fragment_dir("a.bin", b"A\xc3", _decl("e1", "cap", 0, 1))
    config = assemble_config(fragment_dir.responses, fragment_dir.sidecars)
    source = next(item for item in scan(config) if item.rel_path == "a.bin")
    path.write_bytes(b"ZZZ")  # 扫描后、读取前被改写，长度也不同
    loaded = load_fragment(source)
    assert loaded.status == "changed_during_read"
    assert loaded.raw is None

    run(config, now)
    fragment = manifest_reader(config)["assembly"]["fragments"][0]
    # 重新扫描后看到的是改写后的字节，长度不符，同样拒绝组装。
    assert fragment["status"] == "length_mismatch"
    assert fragment["consumed"] is False


def test_budget_exhaustion_reports_unknown(
    fragment_dir, assemble_config, manifest_reader, now
):
    # 两段各 2 字节的备选片段：0..1 有 3 个一致候选，2..3 有 3 个，组合 9 种。
    fragment_dir("a1.bin", b"AB", _decl("e1", "cap", 0, 1))
    fragment_dir("a2.bin", b"AB", _decl("e1", "cap", 0, 1))
    fragment_dir("a3.bin", b"AB", _decl("e1", "cap", 0, 1))
    fragment_dir("b1.bin", b"CD", _decl("e1", "cap", 2, 3))
    fragment_dir("b2.bin", b"CD", _decl("e1", "cap", 2, 3))
    fragment_dir("b3.bin", b"CD", _decl("e1", "cap", 2, 3))
    config = assemble_config(
        fragment_dir.responses,
        fragment_dir.sidecars,
        max_combinations=1,
    )
    run(config, now)
    entity = _entity(manifest_reader(config))
    assert entity["status"] == "budget_exhausted"
    assert entity["complete"] is False
    assert entity["selected"] is None
    assert any("预算" in reason for reason in entity["reasons"])


def test_shared_fragments_across_captures_are_not_merged(
    fragment_dir, assemble_config, manifest_reader, now
):
    shared = b"A\xc3"
    fragment_dir("s0.bin", shared, _decl("e1", "capture-blue", 0, 1))
    fragment_dir("s1.bin", shared, _decl("e1", "capture-red", 0, 1))
    fragment_dir("b2.bin", b"\xa9B", _decl("e1", "capture-blue", 2, 3))
    fragment_dir("r2.bin", b"\xaaB", _decl("e1", "capture-red", 2, 3))
    config = assemble_config(fragment_dir.responses, fragment_dir.sidecars)
    run(config, now)
    entity = _entity(manifest_reader(config))
    assert entity["status"] == "ambiguous"
    groups = {group["capture_id"]: group for group in entity["groups"]}
    assert set(groups) == {"capture-blue", "capture-red"}
    # 相同片段各自留在组内，未跨组共享。
    assert {item["rel_path"] for item in groups["capture-blue"]["fragments"]} == {
        "s0.bin",
        "b2.bin",
    }
    assert {item["rel_path"] for item in groups["capture-red"]["fragments"]} == {
        "s1.bin",
        "r2.bin",
    }
    assert len(entity["shared_fragments"]) == 1


def test_mixed_response_identity_is_not_assembled(
    fragment_dir, assemble_config, manifest_reader, now
):
    fragment_dir("a.bin", b"A\xc3", _decl("e1", "cap-a", 0, 1))
    fragment_dir("b.bin", b"\xa9B", _decl("e2", "cap-a", 2, 3))
    config = assemble_config(fragment_dir.responses, fragment_dir.sidecars)
    run(config, now)
    manifest = manifest_reader(config)
    assert [item["entity_id"] for item in manifest["assembly"]["entities"]] == ["e1", "e2"]
    for entity in manifest["assembly"]["entities"]:
        assert entity["complete"] is False
        assert entity["status"] == "incomplete"


def test_regular_files_unaffected_by_assembly(
    tmp_path, make_config, now, manifest_reader
):
    responses = tmp_path / "responses"
    responses.mkdir()
    (responses / "plain.txt").write_bytes(b"hello world")
    config = make_config(scan_root=responses, assembly={"contract": "consensus"})
    run(config, now)
    manifest = manifest_reader(config)
    assert [item["rel_path"] for item in manifest["files"]] == ["plain.txt"]
    assert manifest["files"][0]["decision"]["encoding"] == "utf-8"
    assert manifest["assembly"]["entities"] == []
    assert manifest["summary"]["files_total"] == 1




def test_declared_source_sha256_mismatch_rejects_fragment(
    fragment_dir, assemble_config, manifest_reader, now
):
    fragment_dir(
        "a.bin",
        b"A\xc3\xa9B",
        _decl("e1", "cap", 0, 3),
        sidecar_extra={"source_sha256": "0" * 64},
    )
    config = assemble_config(fragment_dir.responses, fragment_dir.sidecars)
    run(config, now)
    manifest = manifest_reader(config)
    fragment = manifest["assembly"]["fragments"][0]
    assert fragment["status"] == "source_sha_mismatch"
    assert fragment["consumed"] is False
    assert manifest["assembly"]["entities"][0]["complete"] is False

    # 正确的声明摘要则通过。
    fragment_dir(
        "b.bin",
        b"A\xc3\xa9B",
        _decl("e2", "cap", 0, 3),
        sidecar_extra={"source_sha256": hashlib.sha256(b"A\xc3\xa9B").hexdigest()},
    )
    run(config, now)
    entity = _entity(manifest_reader(config), "e2")
    assert entity["status"] == "complete"


def test_validator_sha256_must_match_assembled_bytes(
    fragment_dir, assemble_config, manifest_reader, now
):
    payload = b"A\xc3\xa9B"
    good = "sha256:" + hashlib.sha256(payload).hexdigest()
    fragment_dir("a.bin", payload, _decl("e1", "cap", 0, 3, validator=good))
    config = assemble_config(fragment_dir.responses, fragment_dir.sidecars)
    run(config, now)
    assert _entity(manifest_reader(config))["status"] == "complete"

    wrong = "sha256:" + "0" * 64
    fragment_dir("b.bin", payload, _decl("e2", "cap", 0, 3, validator=wrong))
    run(config, now)
    entity = _entity(manifest_reader(config), "e2")
    assert entity["status"] == "validator_mismatch"
    assert entity["complete"] is False


def test_same_validator_different_entity_id_are_not_combined(
    fragment_dir, assemble_config, manifest_reader, now
):
    # 相同 validator、相同区间，但 entity_id 不同：必须各自独立。
    fragment_dir("a.bin", b"A\xc3", _decl("e1", "cap", 0, 1, validator="same"))
    fragment_dir("b.bin", b"\xa9B", _decl("e2", "cap", 2, 3, validator="same"))
    config = assemble_config(fragment_dir.responses, fragment_dir.sidecars)
    run(config, now)
    manifest = manifest_reader(config)
    entities = {item["entity_id"]: item for item in manifest["assembly"]["entities"]}
    assert set(entities) == {"e1", "e2"}
    for entity in entities.values():
        assert entity["complete"] is False
        assert entity["status"] == "incomplete"
