"""完全离线的自动交付风险校准与门槛应用。

业务风险是“自动交付了错误的 UTF-8 文本”，而不是编码标签猜中比例。本模块
只用确定性的候选评分（``scorer``）、声明可靠性、严格解码结果与文本等价类
作为输入，在来源组（同一原始网页的多个编码/声明变体）上校准两类发布合同：

* ``forensic_archive``（取证归档）：规范编码标签不确定也必须拒判，即使所有
  候选解码文本相同（例如纯 ASCII 在 utf-8/gb18030/big5 下文本一致）。
* ``search_index``（搜索索引）：只要求交付文本正确；ASCII 等所有候选文本
  相同的输入允许自动交付，但必须记录“编码归因未定”。

流程：定门槛集（tuning）上在有限候选门槛网格中选“满足合同风险预算且覆盖率
最大”的规则，再用完全未参与选择的验证来源组给出独立的单侧 95% 精确上界；
验证不过或证据不足则不推广，应用端对新文件一律拒判（fail-closed）。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from . import RULE_VERSION
from .detectors import canonical_encoding, decode_sample
from .riskstats import clopper_pearson_upper
from .scorer import analyze_candidates, choose_best

CONTRACT_FORENSIC = "forensic_archive"
CONTRACT_SEARCH = "search_index"
CONTRACTS: tuple[str, ...] = (CONTRACT_FORENSIC, CONTRACT_SEARCH)
CALIBRATION_SCHEMA_VERSION = "1.0"
DEFAULT_RISK_BUDGET = 0.05
DEFAULT_CONFIDENCE_LEVEL = 0.95
DEFAULT_VALIDATION_RATIO = 0.3
MIN_SPLIT_GROUPS = 2

REJECT_NO_WINNER = "no_strict_winner"
REJECT_LOW_CONFIDENCE = "below_confidence_threshold"
REJECT_UNRELIABLE_DECLARATION = "reliable_declaration_required"
REJECT_LABEL_UNCERTAIN = "canonical_label_uncertain"
REJECT_NO_PROMOTED_RULE = "no_promoted_rule_for_contract"
REJECT_BINDING_MISMATCH = "rule_binding_mismatch"
ATTRIBUTION_UNRESOLVED = "encoding_attribution_unresolved"


class CalibrationError(ValueError):
    """标注集无效、拆分泄漏或校准输入不满足前置条件。"""


class GateError(RuntimeError):
    """门槛工件无法绑定当前规则/候选集/标注集。"""


@dataclass(frozen=True)
class LabeledSample:
    """一条合成标注：同一来源组可含同一原始字节的多个编码/声明变体。"""

    sample_id: str
    source_group: str
    raw: bytes
    expected_text: str
    allowed_encodings: tuple[str, ...]
    declared_encoding: str | None = None
    note: str = ""


@dataclass(frozen=True)
class SampleFeatures:
    """门槛使用的全部确定性特征；不含任何标注泄漏。"""

    sample_id: str
    source_group: str
    winner_encoding: str | None
    top_score: float
    confidence: float
    margin: float
    declaration_reliable: bool
    declaration_matches_winner: bool
    label_certain: bool
    strict_encodings: tuple[str, ...]
    text_equivalence_class: str
    distinct_texts: int
    winner_text: str | None
    expected_text: str
    allowed_encodings: tuple[str, ...]
    declared_encoding: str | None
    note: str

    @property
    def winner_text_correct(self) -> bool:
        return self.winner_encoding is not None and self.winner_text == self.expected_text

    @property
    def allowed_label_correct(self) -> bool:
        return self.winner_encoding is not None and self.winner_encoding in self.allowed_encodings


@dataclass(frozen=True)
class GateRule:
    """有限候选门槛网格中的一条规则。

    ``require_declaration_match`` 是无标注可观测信号：仅当声明编码本身能严格
    解码且与统计获胜者一致时才允许自动交付，用于压制“分数接近但声明与获胜
    者分歧”的错误文本风险。
    """

    rule_id: str
    contract: str
    min_confidence: float
    require_reliable_declaration: bool
    require_declaration_match: bool
    require_label_certain: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "contract": self.contract,
            "min_confidence": round(self.min_confidence, 6),
            "require_reliable_declaration": self.require_reliable_declaration,
            "require_declaration_match": self.require_declaration_match,
            "require_label_certain": self.require_label_certain,
        }

    def eligible(self, features: SampleFeatures) -> tuple[bool, list[str]]:
        reasons: list[str] = []
        if features.winner_encoding is None:
            reasons.append(REJECT_NO_WINNER)
            return False, reasons
        if features.confidence < self.min_confidence:
            reasons.append(REJECT_LOW_CONFIDENCE)
        if self.require_reliable_declaration and not features.declaration_reliable:
            reasons.append(REJECT_UNRELIABLE_DECLARATION)
        # 无声明不算冲突；仅当存在声明且与统计获胜者分歧时才拒判，
        # 这样无 sidecar 的新文件仍可凭评分证据自动交付。
        if (
            self.require_declaration_match
            and features.declared_encoding is not None
            and not features.declaration_matches_winner
        ):
            reasons.append(REJECT_UNRELIABLE_DECLARATION)
        if self.require_label_certain and not features.label_certain:
            reasons.append(REJECT_LABEL_UNCERTAIN)
        return not reasons, reasons


@dataclass(frozen=True)
class GroupStat:
    split: str
    groups_total: int
    covered_groups: int
    error_groups: int
    coverage: float
    error_rate_observed: float
    error_rate_upper_bound: float
    covered_group_ids: tuple[str, ...]
    error_group_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["coverage"] = round(self.coverage, 6)
        data["error_rate_observed"] = round(self.error_rate_observed, 6)
        data["error_rate_upper_bound"] = round(self.error_rate_upper_bound, 6)
        return data


@dataclass(frozen=True)
class RuleEvaluation:
    rule: GateRule
    tuning: GroupStat
    validation: GroupStat

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule.to_dict(),
            "tuning": self.tuning.to_dict(),
            "validation": self.validation.to_dict(),
        }


@dataclass(frozen=True)
class ContractCalibration:
    contract: str
    risk_budget: float
    confidence_level: float
    promoted: bool
    selected_rule: GateRule | None
    tuning: GroupStat | None
    validation: GroupStat | None
    rejection_reason: str | None
    grid: tuple[RuleEvaluation, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract": self.contract,
            "risk_budget": self.risk_budget,
            "confidence_level": self.confidence_level,
            "promoted": self.promoted,
            "selected_rule": self.selected_rule.to_dict() if self.selected_rule else None,
            "tuning": self.tuning.to_dict() if self.tuning else None,
            "validation": self.validation.to_dict() if self.validation else None,
            "rejection_reason": self.rejection_reason,
            "grid": [item.to_dict() for item in self.grid],
        }


@dataclass(frozen=True)
class GroupAssignment:
    source_group: str
    split: str
    variants: int
    raw_sha256: str
    expected_text_preview: str
    allowed_encodings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CalibrationResult:
    schema_version: str
    rule_version: str
    candidate_encodings: tuple[str, ...]
    annotation_digest: str
    annotation_summary: dict[str, Any]
    split_seed: str
    validation_ratio: float
    group_assignments: tuple[GroupAssignment, ...]
    contracts: tuple[ContractCalibration, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "rule_version": self.rule_version,
            "candidate_encodings": list(self.candidate_encodings),
            "annotation_digest": self.annotation_digest,
            "annotation_summary": self.annotation_summary,
            "split_seed": self.split_seed,
            "validation_ratio": self.validation_ratio,
            "group_assignments": [item.to_dict() for item in self.group_assignments],
            "contracts": [item.to_dict() for item in self.contracts],
        }


@dataclass(frozen=True)
class GateDecision:
    contract: str
    auto_deliver: bool
    encoding: str | None
    confidence: float
    rule_id: str | None
    text_equivalence_class: str
    label_certain: bool
    encoding_attribution_resolved: bool
    reject_reasons: tuple[str, ...]
    risk_budget: float
    validated_upper_bound: float | None
    annotation_digest: str
    rule_version: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract": self.contract,
            "auto_deliver": self.auto_deliver,
            "encoding": self.encoding,
            "confidence": round(self.confidence, 6),
            "rule_id": self.rule_id,
            "text_equivalence_class": self.text_equivalence_class,
            "label_certain": self.label_certain,
            "encoding_attribution_resolved": self.encoding_attribution_resolved,
            "reject_reasons": list(self.reject_reasons),
            "risk_budget": self.risk_budget,
            "validated_error_rate_upper_bound": (
                round(self.validated_upper_bound, 6)
                if self.validated_upper_bound is not None
                else None
            ),
            "annotation_digest": self.annotation_digest,
            "rule_version": self.rule_version,
        }


def _stable_json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def annotation_digest(samples: list[LabeledSample]) -> str:
    payload = [
        {
            "sample_id": item.sample_id,
            "source_group": item.source_group,
            "raw_sha256": hashlib.sha256(item.raw).hexdigest(),
            "expected_text": item.expected_text,
            "allowed_encodings": list(item.allowed_encodings),
            "declared_encoding": item.declared_encoding,
        }
        for item in sorted(samples, key=lambda sample: sample.sample_id)
    ]
    return hashlib.sha256(_stable_json(payload).encode("utf-8")).hexdigest()


def load_annotations(path: str | Path) -> list[LabeledSample]:
    """从离线 JSON 标注文件加载并校验合成标注响应。"""
    source_path = Path(path)
    try:
        payload = json.loads(source_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CalibrationError(f"标注文件无法读取: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("samples"), list):
        raise CalibrationError("标注文件根节点必须是含 samples 数组的对象")

    samples: list[LabeledSample] = []
    seen_ids: set[str] = set()
    seen_raw: dict[bytes, str] = {}
    for index, row in enumerate(payload["samples"]):
        if not isinstance(row, dict):
            raise CalibrationError(f"samples[{index}] 必须是对象")
        try:
            sample_id = str(row["sample_id"])
            source_group = str(row["source_group"])
            raw = base64.b64decode(row["raw_base64"], validate=True)
            expected_text = str(row["expected_text"])
            allowed = tuple(
                canonical_encoding(str(item))
                for item in row["allowed_encodings"]
            )
        except KeyError as exc:
            raise CalibrationError(f"samples[{index}] 缺少字段 {exc.args[0]}") from exc
        except (binascii.Error, TypeError, ValueError) as exc:
            raise CalibrationError(f"samples[{index}] raw_base64 非法: {exc}") from exc
        if not sample_id or not source_group:
            raise CalibrationError(f"samples[{index}] 的 id 与来源组不能为空")
        if sample_id in seen_ids:
            raise CalibrationError(f"重复标注 sample_id: {sample_id}")
        seen_ids.add(sample_id)
        if not allowed or any(not item for item in allowed):
            raise CalibrationError(f"样本 {sample_id} 的 allowed_encodings 不能为空")
        declared = row.get("declared_encoding")
        declared_encoding = canonical_encoding(str(declared)) if declared else None
        prior_group = seen_raw.get(raw)
        if prior_group is not None and prior_group != source_group:
            raise CalibrationError(
                f"同一原始字节出现在多个来源组（{prior_group} 与 {source_group}），"
                "存在训练/验证泄漏风险，拒绝校准"
            )
        seen_raw.setdefault(raw, source_group)
        samples.append(
            LabeledSample(
                sample_id=sample_id,
                source_group=source_group,
                raw=raw,
                expected_text=expected_text,
                allowed_encodings=tuple(dict.fromkeys(allowed)),
                declared_encoding=declared_encoding,
                note=str(row.get("note", "")),
            )
        )

    _validate_group_consistency(samples)
    _validate_label_decoding(samples)
    return samples


def _validate_label_decoding(samples: list[LabeledSample]) -> None:
    """组内一致性确认后再校验允许编码与期望文本，保证冲突标注优先报“冲突”。"""
    for labeled in samples:
        for encoding in labeled.allowed_encodings:
            decoded = decode_sample(labeled.raw, encoding)
            if not decoded.success:
                raise CalibrationError(
                    f"样本 {labeled.sample_id} 的允许编码 {encoding} "
                    "无法严格解码其字节"
                )
            if decoded.text != labeled.expected_text:
                raise CalibrationError(
                    f"样本 {labeled.sample_id} 的允许编码 {encoding} "
                    "严格解码文本与期望文本不一致"
                )


def _validate_group_consistency(samples: list[LabeledSample]) -> None:
    grouped: dict[str, list[LabeledSample]] = {}
    for sample in samples:
        grouped.setdefault(sample.source_group, []).append(sample)
    for group_id, members in grouped.items():
        raw_set = {hashlib.sha256(item.raw).hexdigest() for item in members}
        if len(raw_set) != 1:
            raise CalibrationError(f"来源组 {group_id} 内存在不同原始字节，拒绝校准")
        expected_set = {item.expected_text for item in members}
        if len(expected_set) != 1:
            raise CalibrationError(f"来源组 {group_id} 存在冲突标注：期望文本不一致")
        allowed_set = {item.allowed_encodings for item in members}
        if len(allowed_set) != 1:
            raise CalibrationError(
                f"来源组 {group_id} 存在冲突标注：允许规范编码集合不一致"
            )
        signatures = [
            (item.raw, item.expected_text, item.allowed_encodings, item.declared_encoding)
            for item in members
        ]
        if len(set(signatures)) != len(signatures):
            raise CalibrationError(f"来源组 {group_id} 存在完全重复的标注变体")


def split_groups(
    samples: list[LabeledSample],
    validation_ratio: float = DEFAULT_VALIDATION_RATIO,
    seed: str = "decodebench-calibration-v1",
    forced: dict[str, str] | None = None,
) -> dict[str, tuple[str, ...]]:
    """按来源组确定性拆分为 tuning / validation，组内变体绝不跨集。"""
    if not 0.0 < validation_ratio < 1.0:
        raise CalibrationError("validation_ratio 必须落在 (0, 1)")
    groups = sorted({item.source_group for item in samples})
    if len(groups) < MIN_SPLIT_GROUPS:
        raise CalibrationError("来源组不足以同时构成定门槛集与独立验证集")
    assignment: dict[str, str] = {}
    if forced:
        for group_id, split in forced.items():
            if group_id not in groups:
                raise CalibrationError(f"强制拆分引用了未知来源组: {group_id}")
            if split not in {"tuning", "validation"}:
                raise CalibrationError(f"来源组 {group_id} 的拆分只能是 tuning/validation")
            assignment[group_id] = split
    for group_id in groups:
        if group_id in assignment:
            continue
        digest = hashlib.sha256(f"{seed}|{group_id}".encode("utf-8")).hexdigest()
        rank = int(digest[:12], 16) / 16**12
        assignment[group_id] = "validation" if rank < validation_ratio else "tuning"
    counts = {"tuning": 0, "validation": 0}
    for group_id in groups:
        counts[assignment[group_id]] += 1
    if counts["validation"] == 0 or counts["tuning"] == 0:
        # 极端情况（含强制拆分把全部组压到同一侧）：按确定性顺序迁移，
        # 直到两个集合都非空，且尽量接近目标验证组数。
        ordered = sorted(
            groups,
            key=lambda group_id: hashlib.sha256(
                f"{seed}|fallback|{group_id}".encode("utf-8")
            ).hexdigest(),
        )
        donor = "tuning" if counts["validation"] == 0 else "validation"
        for group_id in ordered:
            if counts["tuning"] > 0 and counts["validation"] > 0:
                break
            if assignment[group_id] != donor:
                continue
            assignment[group_id] = "validation" if donor == "tuning" else "tuning"
            counts[donor] -= 1
            counts["validation" if donor == "tuning" else "tuning"] += 1
        if counts["tuning"] == 0 or counts["validation"] == 0:
            raise CalibrationError("无法同时构成非空的定门槛集与独立验证集")
    tuning = tuple(sorted(g for g in groups if assignment[g] == "tuning"))
    validation = tuple(sorted(g for g in groups if assignment[g] == "validation"))
    if set(tuning) & set(validation):
        raise CalibrationError("拆分泄漏：同一来源组同时进入两个集合")
    return {"tuning": tuning, "validation": validation}


def extract_features(
    samples: list[LabeledSample],
    candidate_encodings: tuple[str, ...],
) -> list[SampleFeatures]:
    """复用 scorer 的确定性候选评分，并计算严格解码文本等价类。"""
    features: list[SampleFeatures] = []
    for sample in samples:
        candidates = analyze_candidates(sample.raw, candidate_encodings)
        winner, confidence = choose_best(candidates)
        strict = [item for item in candidates if item.success]
        text_by_encoding: dict[str, str] = {}
        for item in strict:
            decoded = decode_sample(sample.raw, item.encoding)
            text_by_encoding[item.encoding] = decoded.text
        distinct = sorted(set(text_by_encoding.values()))
        equivalence = hashlib.sha256(
            _stable_json(distinct).encode("utf-8")
        ).hexdigest()[:16]
        indexed = [
            (index, item)
            for index, item in enumerate(candidates)
            if item.success
        ]
        indexed.sort(key=lambda pair: (-pair[1].score, pair[0]))
        runner_up = indexed[1][1].score if len(indexed) > 1 else 0.0
        margin = round(max(0.0, (winner.score if winner else 0.0) - runner_up), 6)
        reliable = False
        matches_winner = False
        if sample.declared_encoding is not None and winner is not None:
            declared_sample = decode_sample(sample.raw, sample.declared_encoding)
            reliable = declared_sample.success
            matches_winner = reliable and sample.declared_encoding == winner.encoding
        features.append(
            SampleFeatures(
                sample_id=sample.sample_id,
                source_group=sample.source_group,
                winner_encoding=winner.encoding if winner else None,
                top_score=round(winner.score, 6) if winner else 0.0,
                confidence=round(confidence, 6),
                margin=margin,
                declaration_reliable=reliable,
                declaration_matches_winner=matches_winner,
                label_certain=len(strict) == 1,
                strict_encodings=tuple(item.encoding for item in strict),
                text_equivalence_class=equivalence,
                distinct_texts=len(distinct),
                winner_text=(
                    text_by_encoding[winner.encoding] if winner is not None else None
                ),
                expected_text=sample.expected_text,
                allowed_encodings=sample.allowed_encodings,
                declared_encoding=sample.declared_encoding,
                note=sample.note,
            )
        )
    return features


def _rule_id(rule: GateRule) -> str:
    digest = hashlib.sha256(_stable_json(rule.to_dict()).encode("utf-8")).hexdigest()[:12]
    return f"gate-{rule.contract}-{digest}"


def build_rule_grid(
    contract: str,
    tuning_features: list[SampleFeatures],
) -> tuple[GateRule, ...]:
    """有限候选门槛：定门槛集观察到的置信度分位点 × 声明要求 × 标签要求。"""
    require_label_certain = contract == CONTRACT_FORENSIC
    thresholds = sorted({item.confidence for item in tuning_features})
    rules: list[GateRule] = []
    for threshold in thresholds:
        for require_reliable in (False, True):
            for require_match in (False, True):
                provisional = GateRule(
                    rule_id="",
                    contract=contract,
                    min_confidence=threshold,
                    require_reliable_declaration=require_reliable,
                    require_declaration_match=require_match,
                    require_label_certain=require_label_certain,
                )
                rules.append(
                    GateRule(
                        rule_id=_rule_id(provisional),
                        contract=contract,
                        min_confidence=threshold,
                        require_reliable_declaration=require_reliable,
                        require_declaration_match=require_match,
                        require_label_certain=require_label_certain,
                    )
                )
    rules.sort(
        key=lambda rule: (
            rule.min_confidence,
            rule.require_reliable_declaration,
            rule.require_declaration_match,
            rule.rule_id,
        )
    )
    return tuple(rules)


def _group_stat(
    rule: GateRule,
    features: list[SampleFeatures],
    split: str,
    confidence_level: float,
) -> GroupStat:
    groups = sorted({item.source_group for item in features})
    covered_ids: set[str] = set()
    error_ids: set[str] = set()
    for item in features:
        eligible, _ = rule.eligible(item)
        if not eligible:
            continue
        covered_ids.add(item.source_group)
        is_error = (
            not item.winner_text_correct
            if rule.contract == CONTRACT_SEARCH
            else (not item.winner_text_correct or not item.allowed_label_correct)
        )
        if is_error:
            error_ids.add(item.source_group)
    total = len(groups)
    covered = len(covered_ids)
    errors = len(error_ids)
    bound = clopper_pearson_upper(errors, covered, confidence_level)
    return GroupStat(
        split=split,
        groups_total=total,
        covered_groups=covered,
        error_groups=errors,
        coverage=(covered / total if total else 0.0),
        error_rate_observed=(errors / covered if covered else 0.0),
        error_rate_upper_bound=bound,
        covered_group_ids=tuple(sorted(covered_ids)),
        error_group_ids=tuple(sorted(error_ids)),
    )


def calibrate_contract(
    contract: str,
    features: list[SampleFeatures],
    split: dict[str, tuple[str, ...]],
    risk_budget: float,
    confidence_level: float,
) -> ContractCalibration:
    if contract not in CONTRACTS:
        raise CalibrationError(f"未知合同: {contract}")
    tuning_features = [
        item for item in features if item.source_group in set(split["tuning"])
    ]
    validation_features = [
        item for item in features if item.source_group in set(split["validation"])
    ]
    grid = build_rule_grid(contract, tuning_features)
    evaluations: list[RuleEvaluation] = []
    for rule in grid:
        tuning_stat = _group_stat(rule, tuning_features, "tuning", confidence_level)
        validation_stat = _group_stat(
            rule, validation_features, "validation", confidence_level
        )
        evaluations.append(
            RuleEvaluation(rule=rule, tuning=tuning_stat, validation=validation_stat)
        )

    qualified = [
        evaluation
        for evaluation in evaluations
        if evaluation.tuning.covered_groups > 0
        and evaluation.tuning.error_rate_upper_bound <= risk_budget
    ]
    if not qualified:
        return ContractCalibration(
            contract=contract,
            risk_budget=risk_budget,
            confidence_level=confidence_level,
            promoted=False,
            selected_rule=None,
            tuning=None,
            validation=None,
            rejection_reason=(
                "定门槛集内没有任何门槛的单侧精确上界满足风险预算"
                "（含样本太少导致零错误上界仍超预算的情形）"
            ),
            grid=tuple(evaluations),
        )
    # 覆盖率最大优先；并列时优先不依赖声明的规则（对无 sidecar 的新文件更
    # 通用），再取置信度门槛更高、约束更严格者。
    qualified.sort(
        key=lambda evaluation: (
            -evaluation.tuning.coverage,
            int(evaluation.rule.require_reliable_declaration),
            int(evaluation.rule.require_declaration_match),
            -evaluation.rule.min_confidence,
            evaluation.rule.rule_id,
        )
    )
    best = qualified[0]
    validation = best.validation
    if validation.covered_groups == 0:
        promoted = False
        reason = "验证集没有任何来源组被该规则覆盖，无法给出独立风险证据"
    elif validation.error_rate_upper_bound > risk_budget:
        promoted = False
        reason = (
            f"独立验证单侧 {confidence_level:.0%} 精确上界 "
            f"{validation.error_rate_upper_bound:.6f} 超过风险预算 {risk_budget:.6f}，"
            "规则不得推广"
        )
    else:
        promoted = True
        reason = None
    return ContractCalibration(
        contract=contract,
        risk_budget=risk_budget,
        confidence_level=confidence_level,
        promoted=promoted,
        # 未推广时也保留最佳规则与两组统计，供报告复核，但应用端不会使用它。
        selected_rule=best.rule,
        tuning=best.tuning,
        validation=validation,
        rejection_reason=reason,
        grid=tuple(evaluations),
    )


def _group_assignments(
    samples: list[LabeledSample],
    split: dict[str, tuple[str, ...]],
) -> tuple[GroupAssignment, ...]:
    grouped: dict[str, list[LabeledSample]] = {}
    for sample in samples:
        grouped.setdefault(sample.source_group, []).append(sample)
    validation_ids = set(split["validation"])
    assignments: list[GroupAssignment] = []
    for group_id in sorted(grouped):
        members = grouped[group_id]
        assignments.append(
            GroupAssignment(
                source_group=group_id,
                split="validation" if group_id in validation_ids else "tuning",
                variants=len(members),
                raw_sha256=hashlib.sha256(members[0].raw).hexdigest(),
                expected_text_preview=members[0].expected_text[:80],
                allowed_encodings=members[0].allowed_encodings,
            )
        )
    return tuple(assignments)


def _annotation_summary(
    samples: list[LabeledSample],
    split: dict[str, tuple[str, ...]],
    assignments: tuple[GroupAssignment, ...],
) -> dict[str, Any]:
    return {
        "annotation_set_id": "",
        "samples_total": len(samples),
        "groups_total": len(assignments),
        "tuning_groups": len(split["tuning"]),
        "validation_groups": len(split["validation"]),
        "group_assignments": [item.to_dict() for item in assignments],
    }


def calibrate(
    samples: list[LabeledSample],
    candidate_encodings: tuple[str, ...],
    *,
    risk_budget: float = DEFAULT_RISK_BUDGET,
    confidence_level: float = DEFAULT_CONFIDENCE_LEVEL,
    validation_ratio: float = DEFAULT_VALIDATION_RATIO,
    seed: str = "decodebench-calibration-v1",
    forced_split: dict[str, str] | None = None,
    annotation_set_id: str = "synthetic-offline-v1",
) -> CalibrationResult:
    """执行完整离线校准并返回绑定规则版本/候选集/标注摘要的结果。"""
    if not 0.0 < risk_budget < 1.0:
        raise CalibrationError("risk_budget 必须落在 (0, 1)")
    if not 0.5 < confidence_level < 1.0:
        raise CalibrationError("confidence_level 必须落在 (0.5, 1)")
    if not samples:
        raise CalibrationError("标注样本为空，无法校准风险门槛")
    canonical_candidates = tuple(
        dict.fromkeys(canonical_encoding(item) for item in candidate_encodings)
    )
    if not canonical_candidates:
        raise CalibrationError("候选编码集合为空，无法校准风险门槛")
    split = split_groups(samples, validation_ratio, seed, forced_split)
    split_lookup = {
        group_id: name
        for name, ids in split.items()
        for group_id in ids
    }
    # 显式守卫：同组变体不得跨集。
    for sample in samples:
        if sample.source_group not in split_lookup:
            raise CalibrationError(f"样本 {sample.sample_id} 的来源组未参与拆分")
    features = extract_features(samples, canonical_candidates)
    contracts = tuple(
        calibrate_contract(contract, features, split, risk_budget, confidence_level)
        for contract in CONTRACTS
    )
    assignments = _group_assignments(samples, split)
    summary = _annotation_summary(samples, split, assignments)
    summary["annotation_set_id"] = annotation_set_id
    return CalibrationResult(
        schema_version=CALIBRATION_SCHEMA_VERSION,
        rule_version=RULE_VERSION,
        candidate_encodings=canonical_candidates,
        annotation_digest=annotation_digest(samples),
        annotation_summary=summary,
        split_seed=seed,
        validation_ratio=validation_ratio,
        group_assignments=assignments,
        contracts=contracts,
    )


def write_calibration(path: str | Path, result: CalibrationResult) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(result.to_dict(), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return target


def load_calibration(path: str | Path) -> CalibrationResult:
    target = Path(path)
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CalibrationError(f"校准工件无法读取: {exc}") from exc
    return calibration_from_dict(payload)


def calibration_from_dict(payload: dict[str, Any]) -> CalibrationResult:
    if str(payload.get("schema_version")) != CALIBRATION_SCHEMA_VERSION:
        raise CalibrationError(
            f"校准工件 schema 版本不被支持: {payload.get('schema_version')}"
        )
    try:
        contracts = tuple(
            ContractCalibration(
                contract=str(item["contract"]),
                risk_budget=float(item["risk_budget"]),
                confidence_level=float(item["confidence_level"]),
                promoted=bool(item["promoted"]),
                selected_rule=(
                    GateRule(**{
                        "rule_id": str(item["selected_rule"]["rule_id"]),
                        "contract": str(item["selected_rule"]["contract"]),
                        "min_confidence": float(item["selected_rule"]["min_confidence"]),
                        "require_reliable_declaration": bool(
                            item["selected_rule"]["require_reliable_declaration"]
                        ),
                        "require_declaration_match": bool(
                            item["selected_rule"]["require_declaration_match"]
                        ),
                        "require_label_certain": bool(
                            item["selected_rule"]["require_label_certain"]
                        ),
                    })
                    if item.get("selected_rule")
                    else None
                ),
                tuning=_group_stat_from_dict(item.get("tuning")),
                validation=_group_stat_from_dict(item.get("validation")),
                rejection_reason=item.get("rejection_reason"),
                grid=tuple(
                    RuleEvaluation(
                        rule=GateRule(**{
                            "rule_id": str(row["rule"]["rule_id"]),
                            "contract": str(row["rule"]["contract"]),
                            "min_confidence": float(row["rule"]["min_confidence"]),
                            "require_reliable_declaration": bool(
                                row["rule"]["require_reliable_declaration"]
                            ),
                            "require_declaration_match": bool(
                                row["rule"]["require_declaration_match"]
                            ),
                            "require_label_certain": bool(
                                row["rule"]["require_label_certain"]
                            ),
                        }),
                        tuning=_group_stat_from_dict(row["tuning"]),
                        validation=_group_stat_from_dict(row["validation"]),
                    )
                    for row in item.get("grid", [])
                ),
            )
            for item in payload["contracts"]
        )
        assignments = tuple(
            GroupAssignment(
                source_group=str(row["source_group"]),
                split=str(row["split"]),
                variants=int(row["variants"]),
                raw_sha256=str(row["raw_sha256"]),
                expected_text_preview=str(row["expected_text_preview"]),
                allowed_encodings=tuple(row["allowed_encodings"]),
            )
            for row in payload["group_assignments"]
        )
        return CalibrationResult(
            schema_version=str(payload["schema_version"]),
            rule_version=str(payload["rule_version"]),
            candidate_encodings=tuple(payload["candidate_encodings"]),
            annotation_digest=str(payload["annotation_digest"]),
            annotation_summary=dict(payload["annotation_summary"]),
            split_seed=str(payload["split_seed"]),
            validation_ratio=float(payload["validation_ratio"]),
            group_assignments=assignments,
            contracts=contracts,
        )
    except KeyError as exc:
        raise CalibrationError(f"校准工件缺少字段: {exc.args[0]}") from exc


def _group_stat_from_dict(row: dict[str, Any] | None) -> GroupStat | None:
    if row is None:
        return None
    return GroupStat(
        split=str(row["split"]),
        groups_total=int(row["groups_total"]),
        covered_groups=int(row["covered_groups"]),
        error_groups=int(row["error_groups"]),
        coverage=float(row["coverage"]),
        error_rate_observed=float(row["error_rate_observed"]),
        error_rate_upper_bound=float(row["error_rate_upper_bound"]),
        covered_group_ids=tuple(row["covered_group_ids"]),
        error_group_ids=tuple(row["error_group_ids"]),
    )


class RiskGate:
    """校准规则在新本地响应上的应用入口；任何绑定异常均 fail-closed。"""

    def __init__(
        self,
        result: CalibrationResult,
        contract: str,
        *,
        candidate_encodings: tuple[str, ...] | None = None,
        rule_version: str = RULE_VERSION,
    ):
        if contract not in CONTRACTS:
            raise GateError(f"未知合同: {contract}")
        self.contract = contract
        self.result = result
        runtime_candidates = (
            tuple(dict.fromkeys(canonical_encoding(item) for item in candidate_encodings))
            if candidate_encodings is not None
            else result.candidate_encodings
        )
        # 候选集合的“有效”定义是运行时集合包含校准时的全部候选：多出的候选
        # 只会提供额外（通常失败的）解码尝试，不会改变既有候选的确定性评分。
        candidates_match = set(result.candidate_encodings).issubset(
            set(runtime_candidates)
        )
        self.binding_ok = result.rule_version == rule_version and candidates_match
        self.binding_detail = {
            "rule_version": {
                "artifact": result.rule_version,
                "runtime": rule_version,
                "match": result.rule_version == rule_version,
            },
            "candidate_encodings": {
                "artifact": list(result.candidate_encodings),
                "runtime": list(runtime_candidates),
                "match": candidates_match,
            },
        }
        calibration = next(
            item for item in result.contracts if item.contract == contract
        )
        self.calibration = calibration
        self.rule = calibration.selected_rule if calibration.promoted else None
        self.risk_budget = calibration.risk_budget
        self.validated_bound = (
            calibration.validation.error_rate_upper_bound
            if calibration.validation is not None
            else None
        )

    @classmethod
    def from_artifact(
        cls,
        path: str | Path,
        contract: str,
        *,
        candidate_encodings: tuple[str, ...] | None = None,
    ) -> "RiskGate":
        return cls(
            load_calibration(path),
            contract,
            candidate_encodings=candidate_encodings,
        )

    def assess(
        self,
        raw: bytes,
        candidate_encodings: tuple[str, ...],
        declared_encoding: str | None = None,
    ) -> GateDecision:
        runtime_candidates = tuple(
            dict.fromkeys(canonical_encoding(item) for item in candidate_encodings)
        )
        sample = LabeledSample(
            sample_id="",
            source_group="",
            raw=raw,
            expected_text="",
            allowed_encodings=(),
            declared_encoding=declared_encoding,
        )
        features = extract_features([sample], runtime_candidates)[0]
        if not self.binding_ok:
            reject_reasons = (REJECT_BINDING_MISMATCH,)
            auto_deliver = False
        elif self.rule is None:
            reject_reasons = (REJECT_NO_PROMOTED_RULE,)
            auto_deliver = False
        else:
            auto_deliver, reject_reasons = self.rule.eligible(features)
        return GateDecision(
            contract=self.contract,
            auto_deliver=auto_deliver,
            encoding=features.winner_encoding,
            confidence=features.confidence,
            rule_id=self.rule.rule_id if self.rule else None,
            text_equivalence_class=features.text_equivalence_class,
            label_certain=features.label_certain,
            encoding_attribution_resolved=features.label_certain,
            reject_reasons=tuple(reject_reasons),
            risk_budget=self.risk_budget,
            validated_upper_bound=self.validated_bound,
            annotation_digest=self.result.annotation_digest,
            rule_version=self.result.rule_version,
        )
