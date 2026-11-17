from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from decodebench.pipeline import run

ROOT = Path(__file__).resolve().parents[1]


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


def test_cli_assemble_responses_requires_enabled_contract(
    tmp_path, make_config, capsys
):
    responses = tmp_path / "responses"
    responses.mkdir()
    (responses / "plain.txt").write_bytes(b"hello")
    config = make_config(scan_root=responses)
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "decodebench",
            "assemble-responses",
            "--config",
            str(config.config_path),
            "--now",
            "2024-01-01T00:00:00Z",
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert process.returncode == 2
    assert "assembly.contract" in process.stderr


def test_cli_assemble_responses_runs_authorized_capture(
    fragment_dir, assemble_config, now
):
    fragment_dir("blue-0.bin", b"A\xc3", _decl("e1", "capture-blue", 0, 1))
    fragment_dir("blue-1.bin", b"\xa9B", _decl("e1", "capture-blue", 2, 3))
    fragment_dir("red-0.bin", b"A\xc3", _decl("e1", "capture-red", 0, 1))
    fragment_dir("red-1.bin", b"\xaaB", _decl("e1", "capture-red", 2, 3))
    config = assemble_config(
        fragment_dir.responses,
        fragment_dir.sidecars,
        contract="consensus",
    )
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "decodebench",
            "assemble-responses",
            "--config",
            str(config.config_path),
            "--contract",
            "authorized_capture",
            "--authorized-capture",
            "capture-blue",
            "--now",
            now,
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert process.returncode == 0, process.stderr
    result = json.loads(process.stdout)
    assert result["assembly"]["entities_complete"] == 1
    manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
    entity = manifest["assembly"]["entities"][0]
    assert entity["capture_id"] == "capture-blue"
    assert entity["assembled_sha256"] == hashlib.sha256(b"A\xc3\xa9B").hexdigest()


def test_ledger_persists_entity_decision_and_fragment_intervals(
    fragment_dir, assemble_config, manifest_reader, now
):
    from decodebench.ledger_queries import list_entities, list_entity_fragments

    fragment_dir("blue-0.bin", b"A\xc3", _decl("e1", "capture-blue", 0, 1))
    fragment_dir("blue-1.bin", b"\xa9B", _decl("e1", "capture-blue", 2, 3))
    fragment_dir("red-0.bin", b"A\xc3", _decl("e1", "capture-red", 0, 1))
    fragment_dir("red-1.bin", b"\xaaB", _decl("e1", "capture-red", 2, 3))
    config = assemble_config(
        fragment_dir.responses,
        fragment_dir.sidecars,
        contract="authorized_capture",
        priority=["capture-blue"],
    )
    result = run(config, now)
    batch_id = result["batch_id"]

    entities = list_entities(config.db_path, batch_id)
    assert len(entities) == 1
    entity = entities[0]
    assert entity["entity_id"] == "e1"
    assert entity["complete"] == 1
    assert entity["capture_id"] == "capture-blue"
    assert entity["final_encoding"] == "utf-8"
    assert entity["assembled_sha256"] == hashlib.sha256(b"A\xc3\xa9B").hexdigest()
    assert entity["output_utf8_sha256"] == hashlib.sha256(b"A\xc3\xa9B").hexdigest()
    assert len(entity["excluded"]) == 1
    assert entity["excluded"][0]["capture_id"] == "capture-red"
    assert entity["excluded"][0]["first_conflict"]["byte_offset"] == 2

    fragments = list_entity_fragments(config.db_path, batch_id, "e1")
    assert [(item["rel_path"], item["byte_start"], item["consumed"]) for item in fragments] == [
        ("blue-0.bin", 0, 1),
        ("blue-1.bin", 2, 1),
        ("red-0.bin", 0, 0),
        ("red-1.bin", 2, 0),
    ]
    assert result["ledger"]["entities_in_batch"] == 1
    assert result["ledger"]["entities_complete"] == 1
    assert result["ledger"]["entities_transcoded"] == 1
    assert result["ledger"]["entity_fragment_rows"] == 4


def test_default_contract_off_keeps_regular_pipeline_for_declared_files(
    fragment_dir, assemble_config, manifest_reader, now
):
    fragment_dir("p0.txt", b"A\xc3", _decl("e1", "cap", 0, 1))
    fragment_dir("p1.txt", b"\xa9B", _decl("e1", "cap", 2, 3))
    config = assemble_config(
        fragment_dir.responses, fragment_dir.sidecars, contract="off"
    )
    run(config, now)
    manifest = manifest_reader(config)
    # off 合同下每个片段仍按普通文件独立处理与转码。
    assert [item["rel_path"] for item in manifest["files"]] == ["p0.txt", "p1.txt"]
    assert manifest["assembly"]["entities"] == []
    assert all(item["transcode"]["success"] for item in manifest["files"])


def test_fragment_declaration_error_is_reported_not_assembled(
    fragment_dir, assemble_config, manifest_reader, now
):
    fragment_dir(
        "bad.bin",
        b"A\xc3",
        {
            "entity_id": "e1",
            "capture_id": "cap",
            "byte_start": 0,
            # 缺少 byte_end_inclusive / entity_size / validator
        },
    )
    fragment_dir("ok.bin", b"\xa9B", _decl("e1", "cap", 2, 3))
    config = assemble_config(fragment_dir.responses, fragment_dir.sidecars)
    run(config, now)
    manifest = manifest_reader(config)
    issues = manifest["assembly"]["declaration_issues"]
    assert len(issues) == 1
    assert issues[0]["rel_path"] == "bad.bin"
    assert issues[0]["status"] == "declaration_error"
    entity = _entity(manifest)
    assert entity["status"] == "incomplete"
    assert [item["rel_path"] for item in entity["fragments"]] == ["ok.bin"]


def test_authorized_capture_falls_through_incomplete_priority_group(
    fragment_dir, assemble_config, manifest_reader, now
):
    # 最高优先的 blue 组缺少 2..3，不完整；应顺延到 red 并保留跳过理由。
    fragment_dir("b0.bin", b"A\xc3", _decl("e1", "capture-blue", 0, 1))
    fragment_dir("r0.bin", b"A\xc3", _decl("e1", "capture-red", 0, 1))
    fragment_dir("r1.bin", b"\xaaB", _decl("e1", "capture-red", 2, 3))
    config = assemble_config(
        fragment_dir.responses,
        fragment_dir.sidecars,
        contract="authorized_capture",
        priority=["capture-blue", "capture-red"],
    )
    run(config, now)
    entity = _entity(manifest_reader(config))
    assert entity["status"] == "complete"
    assert entity["capture_id"] == "capture-red"
    assert entity["assembled_sha256"] == hashlib.sha256(b"A\xc3\xaaB").hexdigest()
    assert any("capture-blue" in reason for reason in entity["reasons"])
    excluded = {row["capture_id"]: row for row in entity["excluded"]}
    assert excluded["capture-blue"]["reason"] == "incomplete"
    assert excluded["capture-blue"]["sha256"] is None
