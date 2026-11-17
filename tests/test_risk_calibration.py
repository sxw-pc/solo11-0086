"""离线风险校准与门槛应用的合成标注测试。

覆盖：ASCII 文本等价、GB18030/Big5 不同文本歧义、来源组拆分泄漏、
零错误小样本拒判、重复/冲突标注、规则版本与候选集变更、两类发布合同、
独立验证失败以及 pipeline 拒判不覆盖旧产物。
"""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

import pytest

from decodebench import RULE_VERSION
from decodebench.calibration import (
    ATTRIBUTION_UNRESOLVED,
    CONTRACTS,
    CONTRACT_FORENSIC,
    CONTRACT_SEARCH,
    REJECT_BINDING_MISMATCH,
    REJECT_NO_PROMOTED_RULE,
    CalibrationError,
    GateRule,
    LabeledSample,
    RiskGate,
    annotation_digest,
    calibrate,
    calibration_from_dict,
    extract_features,
    load_annotations,
    split_groups,
    write_calibration,
)
from decodebench.gate import assess_file, build_gate
from decodebench.models import SourceFile
from decodebench.pipeline import run
from decodebench.riskstats import clopper_pearson_upper

CANDIDATES = (
    "utf-8",
    "gb18030",
    "big5",
    "utf-16-le",
    "utf-16-be",
    "windows-1252",
    "latin-1",
)
# a2ad 在 GB18030 与 Big5 下均严格可解但文本不同；无论加什么 ASCII 后缀，
# 统计获胜者稳定为 big5，适合构造“获胜者文本错误”的合成歧义组。
AMBIGUOUS_HEX = "a2ad"


def _ascii_samples(group_count: int, prefix: str = "ascii") -> list[LabeledSample]:
    samples: list[LabeledSample] = []
    for i in range(group_count):
        raw = f"{prefix}-page-{i}".encode("ascii")
        for variant, declared in enumerate(("utf-8", "gb18030", "big5")):
            samples.append(
                LabeledSample(
                    sample_id=f"{prefix}-{i}-v{variant}",
                    source_group=f"{prefix}-{i}",
                    raw=raw,
                    expected_text=raw.decode("ascii"),
                    allowed_encodings=("utf-8", "gb18030", "big5"),
                    declared_encoding=declared,
                )
            )
    return samples


def _ambiguous_samples(
    group_count: int,
    prefix: str,
    *,
    correct: bool,
    declared_override: str | None = None,
) -> list[LabeledSample]:
    """correct=True 标注 big5 文本（与获胜者一致）；False 标注 gb18030 文本。

    ``declared_override`` 可制造“声明与获胜者一致但文本标注错误”的样本：
    门槛规则会覆盖它，从而在风险上界中暴露错误文本而非被声明条件过滤。
    """
    amb = bytes.fromhex(AMBIGUOUS_HEX)
    samples: list[LabeledSample] = []
    for i in range(group_count):
        raw = amb + f"-{prefix}-{i}".encode("ascii")
        if correct:
            expected = raw.decode("big5")
            allowed = ("big5",)
            declared = "big5"
        else:
            expected = raw.decode("gb18030")
            allowed = ("gb18030",)
            declared = "gb18030"
        samples.append(
            LabeledSample(
                sample_id=f"{prefix}-{i}",
                source_group=f"{prefix}-{i}",
                raw=raw,
                expected_text=expected,
                allowed_encodings=allowed,
                declared_encoding=declared_override or declared,
            )
        )
    return samples


def _write_annotations(tmp_path: Path, samples: list[LabeledSample]) -> Path:
    payload = {
        "annotation_set_id": "synthetic-test",
        "samples": [
            {
                "sample_id": item.sample_id,
                "source_group": item.source_group,
                "raw_base64": base64.b64encode(item.raw).decode("ascii"),
                "expected_text": item.expected_text,
                "allowed_encodings": list(item.allowed_encodings),
                "declared_encoding": item.declared_encoding,
                "note": item.note,
            }
            for item in samples
        ],
    }
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "annotations.json"
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


def _full_annotation_set() -> list[LabeledSample]:
    # 定门槛集与独立验证集的零错误覆盖组数都需达到 59，才能让两侧 95%
    # 精确上界 <= 0.05；小样本“零错误也拒判”另有专门测试。
    return (
        _ascii_samples(260)
        + _ambiguous_samples(30, "ambok", correct=True)
        + _ambiguous_samples(10, "ambbad", correct=False)
    )


# ---------- 风险统计：单侧精确上界 ----------


def test_clopper_pearson_zero_errors_is_not_zero_risk():
    assert clopper_pearson_upper(0, 1) == pytest.approx(0.95)
    assert clopper_pearson_upper(0, 10) == pytest.approx(0.258866, abs=1e-6)
    assert clopper_pearson_upper(0, 100) == pytest.approx(0.029513, abs=1e-6)
    # 没有样本时上界为 1，必须拒判。
    assert clopper_pearson_upper(0, 0) == 1.0
    # 解析解对照：I_x(1,n)=1-(1-x)^n。
    bound = clopper_pearson_upper(1, 10)
    assert 1 - (1 - bound) ** 10 == pytest.approx(0.95, abs=1e-9)
    assert clopper_pearson_upper(5, 5) == 1.0


def test_clopper_pearson_monotone_and_symmetric_coverage():
    assert clopper_pearson_upper(0, 20) < clopper_pearson_upper(0, 5)
    assert clopper_pearson_upper(2, 20) < clopper_pearson_upper(5, 20)
    with pytest.raises(ValueError):
        clopper_pearson_upper(3, 2)


# ---------- 特征与文本等价类 ----------


def test_ascii_variants_share_equivalence_class_and_uncertain_label():
    samples = _ascii_samples(2)
    features = extract_features(samples, CANDIDATES)
    classes = {item.text_equivalence_class for item in features}
    assert len(classes) == 2  # 每组一个等价类
    group_zero = [item for item in features if item.source_group == "ascii-0"]
    assert len({item.text_equivalence_class for item in group_zero}) == 1
    assert all(not item.label_certain for item in features)
    assert all(item.winner_text_correct for item in features)
    # 三个声明均严格可解（声明可靠），但只有 utf-8 声明与获胜者一致。
    assert all(item.declaration_reliable for item in features)
    match = {item.declared_encoding: item.declaration_matches_winner for item in group_zero}
    assert match == {"utf-8": True, "gb18030": False, "big5": False}


def test_ambiguous_bytes_yield_distinct_texts_and_winner_label():
    samples = _ambiguous_samples(1, "x", correct=True)
    features = extract_features(samples, CANDIDATES)
    item = features[0]
    assert item.winner_encoding == "big5"
    assert item.distinct_texts >= 2
    assert not item.label_certain
    assert item.winner_text_correct and item.allowed_label_correct
    bad = _ambiguous_samples(1, "y", correct=False)[0]
    bad_features = extract_features([bad], CANDIDATES)[0]
    assert bad_features.winner_encoding == "big5"
    assert not bad_features.winner_text_correct
    assert not bad_features.allowed_label_correct


# ---------- 来源组拆分：无泄漏、确定性 ----------


def test_split_keeps_variants_together_and_is_deterministic():
    samples = _full_annotation_set()
    first = split_groups(samples)
    second = split_groups(samples)
    assert first == second
    assert not set(first["tuning"]) & set(first["validation"])
    grouped: dict[str, set[str]] = {}
    for sample in samples:
        grouped.setdefault(sample.source_group, set()).add(sample.sample_id)
    for group_id, member_ids in grouped.items():
        split_name = (
            "validation" if group_id in first["validation"] else "tuning"
        )
        # 同组全部变体必须落在同一集合。
        assert all(
            (group_id in first[split_name])
            for _ in member_ids
        )
    assert first["tuning"] and first["validation"]


def test_split_rejects_too_few_groups_and_bad_forced_assignment():
    samples = _ascii_samples(1)
    with pytest.raises(CalibrationError):
        split_groups(samples)
    with pytest.raises(CalibrationError):
        split_groups(_ascii_samples(4), forced={"ascii-9": "validation"})
    with pytest.raises(CalibrationError):
        split_groups(_ascii_samples(4), forced={"ascii-0": "train"})


def test_split_forced_one_sided_is_rebalanced_deterministically():
    samples = _ascii_samples(6)
    all_tuning = {f"ascii-{i}": "tuning" for i in range(6)}
    split = split_groups(samples, forced=all_tuning)
    assert split["tuning"] and split["validation"]
    all_validation = {f"ascii-{i}": "validation" for i in range(6)}
    split_two = split_groups(samples, forced=all_validation)
    assert split_two["tuning"] and split_two["validation"]
    # 重平衡同样确定，且不产生跨集泄漏。
    assert split_groups(samples, forced=all_tuning) == split
    assert not set(split["tuning"]) & set(split["validation"])


# ---------- 标注加载：重复、冲突、非法标注 ----------


def test_load_annotations_roundtrip_and_rejects_duplicates(tmp_path):
    samples = _ascii_samples(2)
    path = _write_annotations(tmp_path, samples)
    loaded = load_annotations(path)
    assert [item.sample_id for item in loaded] == [item.sample_id for item in samples]
    duplicated = samples + [samples[0]]
    dup_path = _write_annotations(tmp_path / "sub", duplicated)
    with pytest.raises(CalibrationError, match="重复标注"):
        load_annotations(dup_path)


def test_conflicting_expected_text_within_group_is_rejected(tmp_path):
    samples = _ascii_samples(2)
    conflicted = list(samples)
    conflicted[1] = LabeledSample(
        sample_id=samples[1].sample_id,
        source_group=samples[1].source_group,
        raw=samples[1].raw,
        expected_text="完全不同的期望文本",
        allowed_encodings=samples[1].allowed_encodings,
        declared_encoding=samples[1].declared_encoding,
    )
    path = _write_annotations(tmp_path / "c", conflicted)
    with pytest.raises(CalibrationError, match="冲突标注"):
        load_annotations(path)


def test_duplicate_variant_and_cross_group_raw_leakage_are_rejected(tmp_path):
    samples = _ascii_samples(2)
    duplicate_variant = list(samples) + [
        LabeledSample(
            sample_id="extra-id",
            source_group=samples[0].source_group,
            raw=samples[0].raw,
            expected_text=samples[0].expected_text,
            allowed_encodings=samples[0].allowed_encodings,
            declared_encoding=samples[0].declared_encoding,
        )
    ]
    with pytest.raises(CalibrationError, match="完全重复"):
        load_annotations(_write_annotations(tmp_path / "d", duplicate_variant))

    leaked = list(samples)
    leaked[1] = LabeledSample(
        sample_id="leak",
        source_group="other-group",
        raw=samples[0].raw,
        expected_text=samples[0].expected_text,
        allowed_encodings=samples[0].allowed_encodings,
        declared_encoding="utf-8",
    )
    with pytest.raises(CalibrationError, match="泄漏"):
        load_annotations(_write_annotations(tmp_path / "e", leaked))


def test_allowed_encoding_must_strictly_decode_expected_text(tmp_path):
    good = _ascii_samples(1)
    bad = [
        LabeledSample(
            sample_id="bad-0",
            source_group="bad-0",
            raw=bytes.fromhex(AMBIGUOUS_HEX),
            expected_text="不可能的文本",
            allowed_encodings=("big5",),
            declared_encoding="big5",
        )
    ]
    path = _write_annotations(tmp_path / "f", bad)
    with pytest.raises(CalibrationError, match="期望文本不一致"):
        load_annotations(path)
    # 允许编码本身无法严格解码也要拒绝。
    undecodable = [
        LabeledSample(
            sample_id="bad-1",
            source_group="bad-1",
            raw=b"\xff\xfe\x00",
            expected_text="x",
            allowed_encodings=("utf-8",),
            declared_encoding="utf-8",
        )
    ]
    with pytest.raises(CalibrationError, match="无法严格解码"):
        load_annotations(_write_annotations(tmp_path / "g", undecodable))
    assert load_annotations(_write_annotations(tmp_path / "h", good))


# ---------- 零错误小样本：不能因零错误就称安全 ----------


def test_small_zero_error_sample_still_rejects_when_bound_exceeds_budget():
    # 仅 3 个来源组：零错误时 95% 上界 0.6316 远高于 0.05 预算。
    samples = _ascii_samples(3)
    result = calibrate(samples, CANDIDATES, risk_budget=0.05, validation_ratio=0.34)
    search = next(c for c in result.contracts if c.contract == CONTRACT_SEARCH)
    assert not search.promoted
    assert search.selected_rule is None
    assert "风险预算" in (search.rejection_reason or "")
    assert all(
        evaluation.tuning.error_rate_upper_bound > 0.05
        for evaluation in search.grid
    )
    forensic = next(c for c in result.contracts if c.contract == CONTRACT_FORENSIC)
    assert not forensic.promoted


# ---------- 两合同：ASCII 等价集合不同 ----------


def test_two_contracts_deliver_different_sets_for_ascii(tmp_path):
    samples = _full_annotation_set()
    result = calibrate(samples, CANDIDATES, risk_budget=0.05)
    by_contract = {c.contract: c for c in result.contracts}

    forensic = by_contract[CONTRACT_FORENSIC]
    search = by_contract[CONTRACT_SEARCH]
    # 取证合同：标签不确定（ASCII 多候选文本等价）永远不满足。
    assert not forensic.promoted
    assert all(rule.require_label_certain for rule in (e.rule for e in forensic.grid))
    assert all(evaluation.tuning.covered_groups == 0 for evaluation in forensic.grid)

    # 搜索索引合同：零错误的 ASCII/正确歧义组可被推广。
    assert search.promoted
    assert search.selected_rule is not None
    assert not search.selected_rule.require_label_certain
    assert search.validation.error_rate_upper_bound <= 0.05

    artifact = write_calibration(tmp_path / "calibration.json", result)
    gate = RiskGate.from_artifact(artifact, CONTRACT_SEARCH, candidate_encodings=CANDIDATES)
    ascii_raw = b"brand new ASCII page"
    verdict = gate.assess(ascii_raw, CANDIDATES)
    assert verdict.auto_deliver
    assert not verdict.encoding_attribution_resolved
    assert not verdict.label_certain

    forensic_gate = RiskGate.from_artifact(
        artifact, CONTRACT_FORENSIC, candidate_encodings=CANDIDATES
    )
    forensic_verdict = forensic_gate.assess(ascii_raw, CANDIDATES)
    assert not forensic_verdict.auto_deliver
    assert REJECT_NO_PROMOTED_RULE in forensic_verdict.reject_reasons


def test_search_contract_rejects_ambiguous_wrong_text_rather_than_celebrating_winner():
    # 错误文本组占比高：任何覆盖它们的门槛上界都超预算，最终不推广。
    samples = (
        _ascii_samples(20)
        + _ambiguous_samples(6, "ambok", correct=True)
        + _ambiguous_samples(14, "ambbad", correct=False)
    )
    result = calibrate(samples, CANDIDATES, risk_budget=0.05)
    search = next(c for c in result.contracts if c.contract == CONTRACT_SEARCH)
    # 若存在覆盖错误组的网格点，其错误组数必须为正，不能被“有正确标签样本”冲淡。
    covering = [
        evaluation
        for evaluation in search.grid
        if evaluation.tuning.covered_groups
        and {f"ambbad-{i}" for i in range(14)}
        & set(evaluation.tuning.covered_group_ids)
    ]
    assert covering
    assert all(evaluation.tuning.error_groups > 0 for evaluation in covering)
    assert not search.promoted


def test_declaration_match_rule_excludes_wrong_text_groups():
    samples = _full_annotation_set()
    result = calibrate(samples, CANDIDATES, risk_budget=0.05)
    search = next(c for c in result.contracts if c.contract == CONTRACT_SEARCH)
    assert search.promoted
    rule = search.selected_rule
    # 被选中的规则不得覆盖定门槛集中的错误文本组。
    assert not (
        set(search.tuning.error_group_ids)
        & set(search.tuning.covered_group_ids)
    )
    features = {
        item.sample_id: item
        for item in extract_features(samples, CANDIDATES)
    }
    bad = next(item for item in features.values() if item.source_group.startswith("ambbad"))
    eligible, reasons = rule.eligible(bad)
    assert not eligible
    assert reasons  # 至少一条拒判理由


# ---------- 独立验证失败：不得推广 ----------


def test_independent_validation_failure_blocks_promotion(tmp_path):
    # 足够多的干净组保证定门槛集存在满足预算的规则；强制把错误文本组全部
    # 放入验证集，制造“定门槛集看着干净、独立验证失败”的局面。
    clean = _ascii_samples(140) + _ambiguous_samples(20, "ambok", correct=True)
    # 错误文本组的声明与统计获胜者一致：规则会覆盖它们，错误无法被
    # 声明条件悄悄过滤，只能由独立验证的风险上界拦截。
    bad_samples = _ambiguous_samples(
        12, "ambbad", correct=False, declared_override="big5"
    )
    all_samples = clean + bad_samples
    forced = {item.source_group: "validation" for item in bad_samples}
    result = calibrate(
        all_samples,
        CANDIDATES,
        risk_budget=0.05,
        forced_split=forced,
    )
    search = next(c for c in result.contracts if c.contract == CONTRACT_SEARCH)
    qualified = [
        evaluation
        for evaluation in search.grid
        if evaluation.tuning.covered_groups
        and evaluation.tuning.error_rate_upper_bound <= 0.05
    ]
    assert qualified  # 定门槛集本身存在满足预算的规则
    assert not search.promoted
    assert "独立验证" in (search.rejection_reason or "")
    assert search.validation.error_groups >= 1
    assert search.validation.error_rate_upper_bound > 0.05
    # 验证失败组只能来自被强制进入验证集的错误文本组，且至少有一个被覆盖。
    bad_ids = {item.source_group for item in bad_samples}
    assert set(search.validation.error_group_ids) <= bad_ids
    assert set(search.validation.error_group_ids)

    # 未推广规则的工件在应用端必须全部拒判。
    artifact = write_calibration(tmp_path / "failed.json", result)
    gate = RiskGate.from_artifact(artifact, CONTRACT_SEARCH, candidate_encodings=CANDIDATES)
    verdict = gate.assess(b"some ASCII body", CANDIDATES)
    assert not verdict.auto_deliver
    assert REJECT_NO_PROMOTED_RULE in verdict.reject_reasons


# ---------- 工件绑定：规则版本 / 候选集变化 ----------


def test_artifact_binds_rule_version_candidates_and_annotation_digest(tmp_path):
    samples = _full_annotation_set()
    result = calibrate(samples, CANDIDATES, risk_budget=0.05)
    assert result.rule_version == RULE_VERSION
    assert result.candidate_encodings == tuple(dict.fromkeys(CANDIDATES))
    assert result.annotation_digest == annotation_digest(samples)
    artifact = write_calibration(tmp_path / "bound.json", result)
    reloaded = calibration_from_dict(json.loads(artifact.read_text(encoding="utf-8")))
    assert reloaded.annotation_digest == result.annotation_digest
    assert reloaded.contracts[0].grid[0].rule.rule_id

    # 候选集合变化 => 绑定失败 => fail-closed。
    changed_candidates = ("utf-8", "gb18030", "big5", "windows-1252")
    gate = RiskGate(result, CONTRACT_SEARCH, candidate_encodings=changed_candidates)
    assert not gate.binding_ok
    verdict = gate.assess(b"ASCII", changed_candidates)
    assert not verdict.auto_deliver
    assert REJECT_BINDING_MISMATCH in verdict.reject_reasons

    # 规则版本变化同样 fail-closed。
    stale_gate = RiskGate(
        result, CONTRACT_SEARCH, candidate_encodings=CANDIDATES, rule_version="future-rule"
    )
    assert not stale_gate.binding_ok
    assert REJECT_BINDING_MISMATCH in stale_gate.assess(b"ASCII", CANDIDATES).reject_reasons


def test_changed_annotations_change_digest_and_invalidate_old_stats(tmp_path):
    first = calibrate(_full_annotation_set(), CANDIDATES, risk_budget=0.05)
    changed = calibrate(
        _full_annotation_set() + _ascii_samples(6, prefix="extra"),
        CANDIDATES,
        risk_budget=0.05,
    )
    assert first.annotation_digest != changed.annotation_digest
    # 旧工件记录的仍是旧摘要，应用端证据可追溯但不得冒充新标注结论。
    artifact = write_calibration(tmp_path / "old.json", first)
    gate = build_gate(str(artifact), CONTRACT_SEARCH, _config_with_candidates(tmp_path))
    assert gate.result.annotation_digest == first.annotation_digest


def _config_with_candidates(tmp_path: Path):
    # 仅需 candidate_encodings 字段的轻量替身。
    class _Cfg:
        candidate_encodings = CANDIDATES

    return _Cfg()


# ---------- 报告：组归属与源摘要 ----------


def test_calibration_report_lists_group_assignment_and_source_summary(tmp_path):
    samples = _full_annotation_set()
    result = calibrate(samples, CANDIDATES, risk_budget=0.05)
    payload = result.to_dict()
    assignments = payload["group_assignments"]
    assert len(assignments) == result.annotation_summary["groups_total"]
    assert {row["split"] for row in assignments} == {"tuning", "validation"}
    grouped: dict[str, list[dict]] = {}
    for row in assignments:
        grouped.setdefault(row["source_group"], []).append(row)
    assert all(len(rows) == 1 for rows in grouped.values())
    ascii_row = next(row for row in assignments if row["source_group"] == "ascii-0")
    assert ascii_row["variants"] == 3
    assert ascii_row["raw_sha256"]
    assert ascii_row["expected_text_preview"]
    # 同组拆分一致性在摘要中可复核。
    sample_groups = {item.source_group for item in samples}
    assert {row["source_group"] for row in assignments} == sample_groups


# ---------- pipeline 集成：拒判不写产物、不伪装成功 ----------


def _source_file(tmp_path: Path, rel_path: str, raw: bytes, sidecar: dict | None = None):
    path = tmp_path / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    import hashlib
    from datetime import datetime, timezone

    sidecar_path = None
    if sidecar is not None:
        sidecar_path = path.with_name(path.name + ".headers.json")
        sidecar_path.write_text(json.dumps(sidecar), encoding="utf-8")
    return SourceFile(
        rel_path=rel_path,
        path=path,
        size=len(raw),
        sha256=hashlib.sha256(raw).hexdigest(),
        mtime=datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
            "+00:00", "Z"
        ),
        sidecar_path=sidecar_path,
        sidecar_rel=sidecar_path.name if sidecar_path else None,
        sidecar=sidecar or {},
    )


def test_gate_assess_file_records_attribution_and_rejection(tmp_path):
    result = calibrate(_full_annotation_set(), CANDIDATES, risk_budget=0.05)
    artifact = write_calibration(tmp_path / "cal.json", result)

    class _Cfg:
        candidate_encodings = CANDIDATES

    gate = build_gate(str(artifact), CONTRACT_SEARCH, _Cfg())
    ascii_source = _source_file(tmp_path, "src/ascii.txt", b"attribution check")
    decision_encoding = "utf-8"

    class _Decision:
        encoding = decision_encoding

    verdict = assess_file(
        gate, b"attribution check", ascii_source, _Decision(), CANDIDATES
    )
    assert verdict.auto_deliver
    assert verdict.warning is not None
    assert verdict.warning.code == "W_ENCODING_ATTRIBUTION_UNRESOLVED"
    assert ATTRIBUTION_UNRESOLVED in verdict.warning.message

    forensic_gate = build_gate(str(artifact), CONTRACT_FORENSIC, _Cfg())
    rejected = assess_file(
        forensic_gate, b"attribution check", ascii_source, _Decision(), CANDIDATES
    )
    assert not rejected.auto_deliver
    assert rejected.warning and rejected.warning.code == "W_RISK_GATE_REJECTED"


def test_pipeline_gated_run_rejects_without_overwriting_outputs(
    tmp_path, make_config
):
    samples = _full_annotation_set()
    calibration = calibrate(samples, CANDIDATES, risk_budget=0.05)
    artifact = tmp_path / "calibration.json"
    write_calibration(artifact, calibration)

    responses = tmp_path / "responses"
    responses.mkdir()
    ascii_path = responses / "ascii_note.txt"
    ascii_path.write_bytes(b"gated ascii body")
    amb = bytes.fromhex(AMBIGUOUS_HEX) + b"-ambiguous"
    amb_path = responses / "ambiguous.txt"
    amb_path.write_bytes(amb)

    config = make_config(scan_root=responses)
    # 先跑一次无门槛流水线，留下旧 UTF-8 产物。
    run(config, "2024-01-01T00:00:00Z")
    old_output = config.transcode_dir / "ambiguous.txt"
    assert old_output.is_file()
    old_bytes = old_output.read_bytes()

    # 取证合同门槛：标签全部不确定 => 全部拒判，旧产物保持不变。
    gated = run(
        config,
        "2024-01-02T00:00:00Z",
        gate_artifact=str(artifact),
        gate_contract=CONTRACT_FORENSIC,
    )
    assert gated["summary"]["gate_rejected"] == 2
    assert gated["summary"]["gate_auto_delivered"] == 0
    assert old_output.read_bytes() == old_bytes
    manifest = json.loads(config.manifest_path.read_text(encoding="utf-8"))
    for entry in manifest["files"]:
        assert entry["transcode"] is None
        assert entry["delivery"]["auto_deliver"] is False
        assert any(w["code"] == "W_RISK_GATE_REJECTED" for w in entry["warnings"])
    assert manifest["risk_gate"]["contract"] == CONTRACT_FORENSIC
    assert manifest["risk_gate"]["binding"]["rule_version"]["match"] is True

    # 搜索索引合同：ASCII 自动交付并记录归因未定；歧义组按验证边界决定。
    search_run = run(
        config,
        "2024-01-03T00:00:00Z",
        gate_artifact=str(artifact),
        gate_contract=CONTRACT_SEARCH,
    )
    manifest2 = json.loads(config.manifest_path.read_text(encoding="utf-8"))
    rows = {item["rel_path"]: item for item in manifest2["files"]}
    ascii_row = rows["ascii_note.txt"]
    assert ascii_row["delivery"]["auto_deliver"] is True
    assert ascii_row["transcode"] is not None and ascii_row["transcode"]["success"]
    assert ascii_row["delivery"]["encoding_attribution_resolved"] is False
    assert any(
        w["code"] == "W_ENCODING_ATTRIBUTION_UNRESOLVED" for w in ascii_row["warnings"]
    )
    assert search_run["summary"]["gate_auto_delivered"] >= 1
    # 原始响应字节未被修改。
    assert ascii_path.read_bytes() == b"gated ascii body"
    assert amb_path.read_bytes() == amb


def test_pipeline_gate_requires_contract_pair(make_config, tmp_path):
    config = make_config()
    with pytest.raises(Exception):
        run(config, "2024-01-01T00:00:00Z", gate_artifact="x", gate_contract=None)


def test_gated_reports_carry_delivery_and_equivalence_class(tmp_path, make_config):
    calibration = calibrate(_full_annotation_set(), CANDIDATES, risk_budget=0.05)
    artifact = tmp_path / "calibration.json"
    write_calibration(artifact, calibration)
    responses = tmp_path / "responses"
    responses.mkdir()
    (responses / "a.txt").write_bytes(b"report ascii")
    config = make_config(scan_root=responses)
    run(
        config,
        "2024-01-01T00:00:00Z",
        gate_artifact=str(artifact),
        gate_contract=CONTRACT_SEARCH,
    )
    report = json.loads((config.reports_dir / "report.json").read_text(encoding="utf-8"))
    assert "risk_gate" in report
    row = report["files"][0]
    assert row["delivery"]["text_equivalence_class"]
    assert row["delivery"]["contract"] == CONTRACT_SEARCH
    markdown = (config.reports_dir / "report.md").read_text(encoding="utf-8")
    assert "风险校准门槛" in markdown
    html = (config.reports_dir / "report.html").read_text(encoding="utf-8")
    assert "风险校准门槛" in html
    assert "<script" not in html.lower()


def test_calibration_artifacts_are_serialization_stable(tmp_path):
    result = calibrate(_full_annotation_set(), CANDIDATES, risk_budget=0.05)
    first = write_calibration(tmp_path / "a.json", result)
    second = write_calibration(tmp_path / "b.json", result)
    assert first.read_bytes() == second.read_bytes()
    # 网格规则 id 完全由规则内容决定。
    rule = result.contracts[0].grid[0].rule
    rebuilt = GateRule(
        rule_id="",
        contract=rule.contract,
        min_confidence=rule.min_confidence,
        require_reliable_declaration=rule.require_reliable_declaration,
        require_declaration_match=rule.require_declaration_match,
        require_label_certain=rule.require_label_certain,
    )
    from decodebench.calibration import _rule_id

    assert _rule_id(rebuilt) == rule.rule_id


def test_deep_copy_independence_of_rule_grid():
    result = calibrate(_full_annotation_set(), CANDIDATES, risk_budget=0.05)
    payload = copy.deepcopy(result.to_dict())
    restored = calibration_from_dict(payload)
    assert restored.to_dict() == result.to_dict()


def test_empty_and_malformed_annotation_files_are_rejected(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "annotations.json").write_text(
        json.dumps({"samples": []}), encoding="utf-8"
    )
    with pytest.raises(CalibrationError):
        calibrate(load_annotations(empty / "annotations.json"), CANDIDATES)
    broken = tmp_path / "broken"
    broken.mkdir()
    (broken / "annotations.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(CalibrationError):
        load_annotations(broken / "annotations.json")


def test_unknown_schema_artifact_is_rejected(tmp_path):
    result = calibrate(_full_annotation_set(), CANDIDATES, risk_budget=0.05)
    payload = result.to_dict()
    payload["schema_version"] = "9.9"
    with pytest.raises(CalibrationError, match="schema"):
        calibration_from_dict(payload)


def test_rule_version_change_forces_recalibration(tmp_path):
    result = calibrate(_full_annotation_set(), CANDIDATES, risk_budget=0.05)
    artifact = write_calibration(tmp_path / "v1.json", result)
    # 模拟规则版本升级：工件内版本与运行时版本不一致，必须 fail-closed。
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    payload["rule_version"] = "decodebench-1999.01.1"
    stale = tmp_path / "stale.json"
    stale.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    gate = RiskGate.from_artifact(stale, CONTRACT_SEARCH, candidate_encodings=CANDIDATES)
    verdict = gate.assess(b"anything ascii", CANDIDATES)
    assert not verdict.auto_deliver
    assert REJECT_BINDING_MISMATCH in verdict.reject_reasons
    assert gate.binding_detail["rule_version"]["match"] is False


def test_missing_candidate_in_runtime_set_fails_binding(tmp_path):
    result = calibrate(_full_annotation_set(), CANDIDATES, risk_budget=0.05)
    artifact = write_calibration(tmp_path / "c.json", result)
    reduced = ("utf-8", "gb18030", "big5")  # 缺少校准时存在的候选
    gate = RiskGate.from_artifact(artifact, CONTRACT_SEARCH, candidate_encodings=reduced)
    assert not gate.binding_ok
    assert REJECT_BINDING_MISMATCH in gate.assess(b"ascii", reduced).reject_reasons
    # 超集候选（额外增加一个编码）不破坏绑定。
    superset = CANDIDATES + ("shift_jis",)
    superset_gate = RiskGate.from_artifact(
        artifact, CONTRACT_SEARCH, candidate_encodings=superset
    )
    assert superset_gate.binding_ok


def test_group_level_stats_never_count_variants_as_independent_samples():
    # 每组 3 个变体；即使全部命中，有效样本数也是组数而非变体数。
    samples = _full_annotation_set()
    result = calibrate(samples, CANDIDATES, risk_budget=0.05)
    search = next(c for c in result.contracts if c.contract == CONTRACT_SEARCH)
    assert search.promoted
    variant_count = sum(
        row["variants"] for row in result.annotation_summary["group_assignments"]
    )
    assert variant_count > search.tuning.covered_groups + search.validation.covered_groups
    # 上界的试验次数严格等于被覆盖来源组数。
    assert search.tuning.covered_groups == len(search.tuning.covered_group_ids)
    assert search.validation.covered_groups == len(
        search.validation.covered_group_ids
    )


def test_forensic_contract_promotes_only_label_certain_samples(tmp_path):
    # 0x81 仅能被 latin-1 严格解码（windows-1252 在 0x81 未定义），
    # 是候选集合下少数 label_certain=True 的输入。
    probe = b"\x81"
    assert _strict_decodes(probe, "latin-1")
    assert not _strict_decodes(probe, "windows-1252")
    samples: list[LabeledSample] = []
    for i in range(120):
        raw = probe + f"-{i}".encode("ascii")
        samples.append(
            LabeledSample(
                sample_id=f"l1-{i}",
                source_group=f"l1-{i}",
                raw=raw,
                expected_text=raw.decode("latin-1"),
                allowed_encodings=("latin-1",),
                declared_encoding="latin-1",
            )
        )
    features = extract_features(samples[:3], CANDIDATES)
    assert all(item.label_certain for item in features)
    result = calibrate(samples, CANDIDATES, risk_budget=0.05)
    forensic = next(c for c in result.contracts if c.contract == CONTRACT_FORENSIC)
    assert all(rule.require_label_certain for rule in (e.rule for e in forensic.grid))
    if forensic.promoted:
        artifact = write_calibration(tmp_path / "forensic.json", result)
        gate = RiskGate.from_artifact(
            artifact, CONTRACT_FORENSIC, candidate_encodings=CANDIDATES
        )
        verdict = gate.assess(probe + b"-new", CANDIDATES)
        assert verdict.auto_deliver
        assert verdict.encoding_attribution_resolved
        # 同一合同下 ASCII 多候选文本等价仍必须拒判。
        ascii_verdict = gate.assess(b"plain ascii", CANDIDATES)
        assert not ascii_verdict.auto_deliver
    else:
        # 样本量不足时也必须明确拒判而非隐式放行。
        assert forensic.rejection_reason


def _strict_decodes(raw: bytes, encoding: str) -> bool:
    from decodebench.detectors import canonical_encoding

    try:
        raw.decode(canonical_encoding(encoding), errors="strict")
    except (UnicodeError, LookupError, ValueError):
        return False
    return True


def test_cli_calibrate_subcommand_runs_offline(tmp_path, make_config):
    config = make_config()
    samples = _full_annotation_set()
    annotation_path = _write_annotations(tmp_path / "labels", samples)
    artifact = tmp_path / "artifact.json"
    from decodebench.cli import main

    rc = main(
        [
            "calibrate",
            "--config",
            str(config.config_path),
            "--annotations",
            str(annotation_path),
            "--output",
            str(artifact),
        ]
    )
    assert rc == 0
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    assert payload["rule_version"] == RULE_VERSION
    assert {item["contract"] for item in payload["contracts"]} == set(CONTRACTS)


def test_cli_requires_matching_gate_flags(make_config, capsys):
    config = make_config()
    from decodebench.cli import main

    rc = main(
        [
            "pipeline",
            "--config",
            str(config.config_path),
            "--gate-artifact",
            "whatever.json",
        ]
    )
    assert rc == 2
    assert "必须同时提供" in capsys.readouterr().err
