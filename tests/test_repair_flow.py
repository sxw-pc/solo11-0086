"""离线可逆乱码修复候选与人工批准流程测试。

覆盖：
- 混合真实字面量与误码同形片段：两处分别列出，未批准不替换；
- 不可逆 U+FFFD：只能进入 ineligible/blocked，不能批准；
- 相互重叠的候选：全部 blocked，拒绝自动发布；
- 源文件改变后旧批准因 SHA-256 不匹配而失效；
- 严格路径与逐字符逆向校验、位置漂移与摘要篡改拒绝；
- 独立修复副本不触碰源文件与原转码产物；
- 重复执行同一批准幂等；
- 台账可追溯。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from decodebench.cli import main as cli_main
from decodebench.ledger_queries import list_repair_approvals, list_repair_items
from decodebench.mojibake import build_repair_candidates
from decodebench.pipeline import run
from decodebench.repair import (
    REPAIR_SCHEMA_VERSION,
    RepairError,
    apply_approval,
    load_approval,
    make_approval_template,
    validate_approval,
)

NOW = "2024-03-01T00:00:00Z"
APPLY_NOW = "2024-03-02T00:00:00Z"


def _write_source(root: Path, name: str, text: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / name
    path.write_text(text, encoding="utf-8")
    return path


def _mojibake(original: str, wrong: str = "windows-1252") -> str:
    return original.encode("utf-8").decode(wrong)


@pytest.fixture
def mixed_config(tmp_path, make_config):
    responses = tmp_path / "responses"
    sidecars = tmp_path / "sidecars"
    sidecars.mkdir(parents=True, exist_ok=True)
    literal = "真实字面Ã©与"
    mojibake_part = _mojibake("café")
    text = literal + " 分隔 " + mojibake_part + " 结尾\n"
    _write_source(responses, "mixed.txt", text)
    config = make_config(scan_root=responses, sidecar_root=sidecars)
    return config, text


def _make_config(tmp_path, make_config, responses: Path, **kwargs):
    sidecars = tmp_path / "sidecars"
    sidecars.mkdir(parents=True, exist_ok=True)
    return make_config(scan_root=responses, sidecar_root=sidecars, **kwargs)


def _run_pipeline(config):
    return run(config, NOW)


def _candidates_of(document: dict, rel_path: str) -> list[dict]:
    row = next(item for item in document["files"] if item["rel_path"] == rel_path)
    return row["candidates"]


# ---------------------------------------------------------------------------
# 候选生成：严格路径、逐字符可逆、同形片段分别列出
# ---------------------------------------------------------------------------


def test_literal_and_mojibake_same_shape_listed_separately(mixed_config):
    config, text = mixed_config
    _run_pipeline(config)
    document = json.loads(
        config.repair_candidates_path.read_text(encoding="utf-8")
    )
    candidates = _candidates_of(document, "mixed.txt")
    # 真实字面 Ã© 与误码 Ã© 各产生一个候选，偏移不同
    assert len(candidates) == 2
    positions = [(c["position"]["start_char"], c["position"]["end_char"]) for c in candidates]
    assert positions == sorted(positions)
    assert len({p[0] for p in positions}) == 2
    for candidate in candidates:
        assert candidate["fragment"] == "Ã©"
        assert candidate["repaired"] == "é"
        assert candidate["status"] == "candidate"
        assert candidate["reversible"] is True
        assert candidate["position"]["start_byte"] < candidate["position"]["end_byte"]
        assert candidate["route"]["route_id"] == "utf-8<-windows-1252"
        # 严格路径证据可独立复算
        rebuilt = candidate["fragment"].encode(
            candidate["route"]["wrong_encoding"], errors="strict"
        ).decode(candidate["route"]["target_encoding"], errors="strict")
        assert rebuilt == candidate["repaired"]
        # 逐字符逆向还原等于原片段
        restored = candidate["repaired"].encode(
            candidate["route"]["target_encoding"], errors="strict"
        ).decode(candidate["route"]["wrong_encoding"], errors="strict")
        assert restored == candidate["fragment"]
        # 候选身份绑定源摘要、裁决编码、位置、路径与目标片段摘要
        assert candidate["candidate_id"].startswith("rc_")
        assert candidate["source_sha256"]


def test_typical_match_alone_is_not_a_candidate_without_roundtrip(tmp_path, make_config):
    responses = tmp_path / "responses"
    # 真实字面 Ã© 嵌在无法按 windows-1252 重编码的 CJK 段落里：
    # 整段窗口无法通过严格路径，只有独立的 Ã© 窗口可逆向。
    _write_source(responses, "literal.txt", "前缀Ã©后缀")
    findings = build_repair_candidates(
        "literal.txt",
        hashlib.sha256((responses / "literal.txt").read_bytes()).hexdigest(),
        "utf-8",
        (responses / "literal.txt").read_text(encoding="utf-8"),
        "literal.txt",
        "digest",
    )
    assert all(c.status == "candidate" for c in findings.candidates)
    assert {c.fragment for c in findings.candidates} == {"Ã©"}
    # 无法逆向的窗口必须记录为 ineligible 而不是静默丢弃
    assert findings.ineligible
    assert all(item.reason.startswith("irreversible") for item in findings.ineligible)


def test_replacement_char_is_irreversible_and_never_candidate(tmp_path, make_config):
    responses = tmp_path / "responses"
    text = "损坏" + "�" + " 与 " + _mojibake("café")
    _write_source(responses, "fffd.txt", text)
    config = _make_config(
        tmp_path, make_config, responses, transcode_errors="replace"
    )
    _run_pipeline(config)
    document = json.loads(config.repair_candidates_path.read_text(encoding="utf-8"))
    row = next(item for item in document["files"] if item["rel_path"] == "fffd.txt")
    # 含 U+FFFD 的窗口不允许成为候选
    assert all("�" not in c["fragment"] for c in row["candidates"])
    replacement_spans = [
        item for item in row["ineligible_spans"] if item["reason"] == "irreversible_replacement"
    ]
    assert replacement_spans
    assert all("U+FFFD" in item["detail"] for item in replacement_spans)


def test_overlapping_candidates_are_blocked(tmp_path, make_config):
    responses = tmp_path / "responses"
    # 两个典型 mojibake 序列直接相邻形成同一非 ASCII 连续段，
    # 单序列窗口与跨序列窗口互相重叠。
    text = _mojibake("é") + _mojibake("è")
    _write_source(responses, "overlap.txt", text)
    config = _make_config(tmp_path, make_config, responses)
    _run_pipeline(config)
    document = json.loads(config.repair_candidates_path.read_text(encoding="utf-8"))
    candidates = _candidates_of(document, "overlap.txt")
    assert len(candidates) >= 3
    assert all(c["status"] == "blocked" for c in candidates)
    assert all(c["blocked_reasons"] == ["overlapping_candidates"] for c in candidates)
    assert all(c["overlap_with"] for c in candidates)
    assert document["summary"]["candidates_blocked"] == len(candidates)
    assert document["summary"]["candidates_pending"] == 0


def test_clean_text_has_no_candidates(tmp_path, make_config):
    responses = tmp_path / "responses"
    _write_source(responses, "clean.txt", "正常的中文正文与 ASCII text。\n")
    config = _make_config(tmp_path, make_config, responses)
    _run_pipeline(config)
    document = json.loads(config.repair_candidates_path.read_text(encoding="utf-8"))
    row = next(item for item in document["files"] if item["rel_path"] == "clean.txt")
    assert row["candidates"] == []


# ---------------------------------------------------------------------------
# 批准模板与校验
# ---------------------------------------------------------------------------


def _approval_for(document: dict, decisions: dict[str, str], approver: str = "reviewer-a") -> dict:
    template = make_approval_template(document)
    for entry in template["entries"]:
        entry["decision"] = decisions.get(entry["candidate_id"], "keep_original")
    template["approver"] = approver
    template["approved_at"] = APPLY_NOW
    template["note"] = "离线人工复核"
    return template


def test_approval_template_defaults_to_keep_and_carries_bindings(mixed_config):
    config, _ = mixed_config
    _run_pipeline(config)
    document = json.loads(config.repair_candidates_path.read_text(encoding="utf-8"))
    template = make_approval_template(document)
    assert template["schema_version"] == REPAIR_SCHEMA_VERSION
    assert template["approval_kind"] == "mojibake_repair"
    assert all(entry["decision"] == "keep_original" for entry in template["entries"])
    binding = template["bindings"][0]
    assert binding["rel_path"] == "mixed.txt"
    assert binding["source_sha256"] and binding["encoding"] == "utf-8"
    assert len(template["entries"]) == 2


def test_blocked_candidate_cannot_be_approved(tmp_path, make_config):
    responses = tmp_path / "responses"
    _write_source(responses, "overlap.txt", _mojibake("é") + _mojibake("è"))
    config = _make_config(tmp_path, make_config, responses)
    _run_pipeline(config)
    document = json.loads(config.repair_candidates_path.read_text(encoding="utf-8"))
    findings = _rebuild_findings(config)
    blocked_id = document["files"][0]["candidates"][0]["candidate_id"]
    approval = _approval_for(document, {blocked_id: "approve_candidate"})
    with pytest.raises(RepairError, match="blocked"):
        validate_approval(approval, findings)


# ---------------------------------------------------------------------------
# 批准执行：两条业务路线、隔离、可追溯、幂等
# ---------------------------------------------------------------------------


def _rebuild_findings(config):
    from decodebench.cli import _rebuild_repair_findings

    return _rebuild_repair_findings(config)


def _write_approval(path: Path, approval: dict) -> Path:
    path.write_text(json.dumps(approval, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def test_approve_only_selected_fragment_keeps_literal_and_products(mixed_config):
    config, source_text = mixed_config
    _run_pipeline(config)
    document = json.loads(config.repair_candidates_path.read_text(encoding="utf-8"))
    candidates = _candidates_of(document, "mixed.txt")
    mojibake_candidate = max(candidates, key=lambda item: item["position"]["start_char"])
    literal_candidate = min(candidates, key=lambda item: item["position"]["start_char"])
    approval = _approval_for(
        document, {mojibake_candidate["candidate_id"]: "approve_candidate"}
    )
    approval_path = _write_approval(config.out_dir / "approval.json", approval)

    source_before = (config.scan_root / "mixed.txt").read_bytes()
    transcode_before = (config.transcode_dir / "mixed.txt").read_bytes()
    findings = _rebuild_findings(config)
    applied = apply_approval(
        approval_path, findings, config.transcode_dir, config.repair_dir, now=APPLY_NOW
    )
    assert len(applied) == 1
    assert applied[0].disposition == "approved_repair"
    assert applied[0].approved_candidate_ids == [mojibake_candidate["candidate_id"]]
    assert applied[0].kept_candidate_ids == [literal_candidate["candidate_id"]]

    # 源文件与原转码产物及其摘要不变
    assert (config.scan_root / "mixed.txt").read_bytes() == source_before
    assert (config.transcode_dir / "mixed.txt").read_bytes() == transcode_before
    assert applied[0].transcode_output_sha256 == hashlib.sha256(transcode_before).hexdigest()

    repair_text = (config.repair_dir / "mixed.txt").read_text(encoding="utf-8")
    # 真实字面 Ã© 原样保留；只有获批的误码片段变为 é
    assert "真实字面Ã©与" in repair_text
    assert "café" in repair_text
    assert "cafÃ©" not in repair_text
    assert repair_text.count("Ã©") == 1
    assert applied[0].repair_sha256 == hashlib.sha256(
        (config.repair_dir / "mixed.txt").read_bytes()
    ).hexdigest()
    # 修复副本与转码产物是不同文件
    assert config.repair_dir != config.transcode_dir


def test_keep_original_route_archives_identical_copy_with_risk_record(mixed_config):
    config, _ = mixed_config
    _run_pipeline(config)
    document = json.loads(config.repair_candidates_path.read_text(encoding="utf-8"))
    approval = _approval_for(document, {})  # 全部 keep_original
    approval_path = _write_approval(config.out_dir / "keep.json", approval)
    transcode_before = (config.transcode_dir / "mixed.txt").read_bytes()

    applied = apply_approval(
        approval_path, _rebuild_findings(config),
        config.transcode_dir, config.repair_dir, now=APPLY_NOW,
    )
    assert applied[0].disposition == "kept_original"
    assert applied[0].approved_candidate_ids == []
    assert len(applied[0].kept_candidate_ids) == 2
    repair_bytes = (config.repair_dir / "mixed.txt").read_bytes()
    assert repair_bytes == transcode_before
    assert applied[0].repair_sha256 == applied[0].transcode_output_sha256
    record = json.loads(
        (config.repair_dir / "applied_repairs.json").read_text(encoding="utf-8")
    )
    assert record["approval_sha256"] == hashlib.sha256(
        approval_path.read_bytes()
    ).hexdigest()
    assert record["repairs"][0]["disposition"] == "kept_original"


def test_apply_is_idempotent_for_same_approval(mixed_config):
    config, _ = mixed_config
    _run_pipeline(config)
    document = json.loads(config.repair_candidates_path.read_text(encoding="utf-8"))
    candidate_id = document["files"][0]["candidates"][-1]["candidate_id"]
    approval = _approval_for(document, {candidate_id: "approve_candidate"})
    approval_path = _write_approval(config.out_dir / "approval.json", approval)
    findings = _rebuild_findings(config)

    first = apply_approval(
        approval_path, findings, config.transcode_dir, config.repair_dir, now=APPLY_NOW
    )
    repair_first = (config.repair_dir / "mixed.txt").read_bytes()
    second = apply_approval(
        approval_path, findings, config.transcode_dir, config.repair_dir,
        now="2024-03-03T00:00:00Z",
    )
    assert (config.repair_dir / "mixed.txt").read_bytes() == repair_first
    assert first[0].repair_sha256 == second[0].repair_sha256
    assert first[0].approval_sha256 == second[0].approval_sha256


def test_stale_approval_fails_after_source_change(mixed_config):
    config, _ = mixed_config
    _run_pipeline(config)
    document = json.loads(config.repair_candidates_path.read_text(encoding="utf-8"))
    approval = _approval_for(
        document, {document["files"][0]["candidates"][0]["candidate_id"]: "approve_candidate"}
    )
    approval_path = _write_approval(config.out_dir / "approval.json", approval)

    source = config.scan_root / "mixed.txt"
    original = source.read_bytes()
    try:
        source.write_bytes(original + b" ")
        with pytest.raises(RepairError, match="SHA-256"):
            validate_approval(load_approval(approval_path), _rebuild_findings(config))
        # 失败不得产生任何修复副本
        assert not (config.repair_dir / "mixed.txt").exists()
    finally:
        source.write_bytes(original)


def test_target_digest_tampering_is_rejected(mixed_config):
    config, _ = mixed_config
    _run_pipeline(config)
    document = json.loads(config.repair_candidates_path.read_text(encoding="utf-8"))
    approval = _approval_for(document, {})
    approval["entries"][0]["target_fragment_sha256"] = "0" * 64
    approval_path = _write_approval(config.out_dir / "tampered.json", approval)
    with pytest.raises(RepairError, match="摘要不匹配"):
        apply_approval(
            approval_path, _rebuild_findings(config),
            config.transcode_dir, config.repair_dir, now=APPLY_NOW,
        )


def test_unknown_candidate_and_missing_approver_are_rejected(mixed_config):
    config, _ = mixed_config
    _run_pipeline(config)
    document = json.loads(config.repair_candidates_path.read_text(encoding="utf-8"))
    approval = _approval_for(document, {})
    approval["entries"][0]["candidate_id"] = "rc_0000000000000000"
    approval_path = _write_approval(config.out_dir / "unknown.json", approval)
    with pytest.raises(RepairError, match="不存在"):
        validate_approval(load_approval(approval_path), _rebuild_findings(config))

    approval = _approval_for(document, {})
    approval["approver"] = ""
    approval_path = _write_approval(config.out_dir / "noapprover.json", approval)
    with pytest.raises(RepairError, match="approver"):
        load_approval(approval_path)


def test_position_drift_is_rejected_at_apply(tmp_path):
    from decodebench.repair import FileRepairFindings

    old_text = "a" + _mojibake("é")
    findings = build_repair_candidates(
        "x.txt", "s" * 64, "utf-8", old_text, "x.txt", None
    )
    candidate = findings.candidates[0]
    approval = {
        "schema_version": REPAIR_SCHEMA_VERSION,
        "approval_kind": "mojibake_repair",
        "approver": "reviewer-a",
        "approved_at": APPLY_NOW,
        "bindings": [
            {
                "rel_path": "x.txt",
                "source_sha256": "s" * 64,
                "encoding": "utf-8",
                "transcode_output_sha256": None,
            }
        ],
        "entries": [
            {
                "rel_path": "x.txt",
                "candidate_id": candidate.candidate_id,
                "decision": "approve_candidate",
                "target_fragment_sha256": candidate.repaired_sha256,
                "note": "",
            }
        ],
    }
    validate_approval(approval, [findings])
    drifted_text = "ab" + _mojibake("é")  # 片段整体后移一个字符
    root = tmp_path / "drift"
    transcode_dir = root / "transcoded"
    repair_dir = root / "repair"
    transcode_dir.mkdir(parents=True)
    (transcode_dir / "x.txt").write_text(drifted_text, encoding="utf-8")
    approval_path = root / "approval.json"
    _write_approval(approval_path, approval)
    # 转码产物摘要不匹配时优先报摘要错误；这里对齐摘要后应报位置漂移
    matched = FileRepairFindings(
        rel_path=findings.rel_path,
        source_sha256=findings.source_sha256,
        encoding=findings.encoding,
        transcode_output_rel_path="x.txt",
        transcode_output_sha256=hashlib.sha256(
            drifted_text.encode("utf-8")
        ).hexdigest(),
    )
    matched.candidates = findings.candidates
    with pytest.raises(RepairError, match="位置漂移"):
        apply_approval(
            approval_path, [matched], transcode_dir, repair_dir, now=APPLY_NOW
        )
    assert not (repair_dir / "x.txt").exists()


# ---------------------------------------------------------------------------
# 端到端 CLI 与台账
# ---------------------------------------------------------------------------


def test_cli_candidates_and_apply_end_to_end(mixed_config, tmp_path):
    config, _ = mixed_config
    assert cli_main(["pipeline", "--config", str(config.config_path), "--now", NOW]) == 0
    template_path = tmp_path / "approval.json"
    assert (
        cli_main(
            [
                "repair-candidates",
                "--config",
                str(config.config_path),
                "--output",
                str(template_path),
            ]
        )
        == 0
    )
    document = json.loads(config.repair_candidates_path.read_text(encoding="utf-8"))
    approval = json.loads(template_path.read_text(encoding="utf-8"))
    mojibake_id = max(
        document["files"][0]["candidates"],
        key=lambda item: item["position"]["start_char"],
    )["candidate_id"]
    for entry in approval["entries"]:
        if entry["candidate_id"] == mojibake_id:
            entry["decision"] = "approve_candidate"
    approval["approver"] = "reviewer-cli"
    approval["approved_at"] = APPLY_NOW
    _write_approval(template_path, approval)

    source_before = (config.scan_root / "mixed.txt").read_bytes()
    assert (
        cli_main(
            [
                "repair-apply",
                "--config",
                str(config.config_path),
                "--approval",
                str(template_path),
                "--now",
                APPLY_NOW,
            ]
        )
        == 0
    )
    # 源文件未被 CLI 触碰
    assert (config.scan_root / "mixed.txt").read_bytes() == source_before
    repair_text = (config.repair_dir / "mixed.txt").read_text(encoding="utf-8")
    assert "café" in repair_text and "真实字面Ã©" in repair_text

    rows = list_repair_approvals(config.db_path)
    assert len(rows) == 1
    assert rows[0]["approver"] == "reviewer-cli"
    assert rows[0]["approved_count"] == 1
    assert rows[0]["kept_count"] == 1
    items = list_repair_items(config.db_path, rows[0]["approval_id"])
    assert len(items) == 2
    assert {item["disposition"] for item in items} == {
        "approved_repair",
        "kept_original",
    }
    approved_item = next(item for item in items if item["disposition"] == "approved_repair")
    assert approved_item["source_sha256"] == hashlib.sha256(source_before).hexdigest()
    assert approved_item["repair_sha256"] == hashlib.sha256(
        (config.repair_dir / "mixed.txt").read_bytes()
    ).hexdigest()


def test_ledger_recording_is_idempotent(mixed_config):
    from decodebench.ledger import record_repairs

    config, _ = mixed_config
    _run_pipeline(config)
    document = json.loads(config.repair_candidates_path.read_text(encoding="utf-8"))
    approval = _approval_for(
        document, {document["files"][0]["candidates"][0]["candidate_id"]: "approve_candidate"}
    )
    approval_path = _write_approval(config.out_dir / "approval.json", approval)
    applied = apply_approval(
        approval_path, _rebuild_findings(config),
        config.transcode_dir, config.repair_dir, now=APPLY_NOW,
    )
    approval_sha = hashlib.sha256(approval_path.read_bytes()).hexdigest()
    payload = [item.to_dict() for item in applied]
    first = record_repairs(config, approval, approval_sha, payload, APPLY_NOW)
    second = record_repairs(config, approval, approval_sha, payload, APPLY_NOW)
    assert first["approval_id"] == second["approval_id"]
    connection = sqlite3.connect(config.db_path)
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM repair_approvals WHERE approval_sha256 = ?",
            (approval_sha,),
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM repair_items WHERE approval_id = ?",
            (first["approval_id"],),
        ).fetchone()[0] == 2
    finally:
        connection.close()


def test_pipeline_manifest_carries_candidate_evidence_and_is_stable(mixed_config):
    config, _ = mixed_config
    first = _run_pipeline(config)
    manifest = json.loads(config.manifest_path.read_text(encoding="utf-8"))
    entry = next(item for item in manifest["files"] if item["rel_path"] == "mixed.txt")
    assert entry["repair_candidates"]["candidate_count"] == 2
    assert entry["repair_candidates"]["transcode_output_sha256"] == (
        entry["transcode"]["output_sha256"]
    )
    # 重复运行候选清单字节稳定
    first_doc = config.repair_candidates_path.read_bytes()
    _run_pipeline(config)
    assert config.repair_candidates_path.read_bytes() == first_doc
    assert "repair_candidates" in first
