"""按固定优先级裁决编码，并输出冲突、置信度与警告。"""

from __future__ import annotations

from . import CONFLICT_CODES, ERROR_CODES
from .config import Config
from .detectors import canonical_encoding, compatible_encoding
from .evidence import all_declared, apply_decision_matches, declaration_values
from .models import CandidateResult, Decision, Evidence, SourceFile, WarningItem
from .scorer import choose_best, ranking

_METHOD_CONFIDENCE = {
    "bom": 0.995,
    "http_header": 0.92,
    "xml_declaration": 0.90,
    "meta_charset": 0.88,
    "fallback": 0.72,
}
_SEVERITY = {
    "E_BOM_DECL_CONFLICT": "high",
    "E_BOM_HEADER_CONFLICT": "high",
    "E_HEADER_DECL_CONFLICT": "high",
    "E_DOC_DECL_CONFLICT": "high",
    "E_HEADER_BYTE_CONFLICT": "high",
    "E_META_BYTE_CONFLICT": "medium",
    "E_DECL_BYTE_CONFLICT": "medium",
    "E_DECLARATION_UNDECODABLE": "high",
    "E_UNDECODABLE": "high",
    "E_LOW_CONFIDENCE": "medium",
    "W_FALLBACK_USED": "low",
    "W_STATISTICAL_DECISION": "low",
    "W_SIDECAR_INVALID": "medium",
}


def _try_decode(raw: bytes, encoding: str) -> bool:
    try:
        raw.decode(canonical_encoding(encoding), errors="strict")
        return True
    except (UnicodeError, LookupError, ValueError):
        return False


def _pair_code(left: str, right: str) -> str:
    sources = {left, right}
    if "bom" in sources and "http_header" in sources:
        return "E_BOM_HEADER_CONFLICT"
    if "bom" in sources:
        return "E_BOM_DECL_CONFLICT"
    if "http_header" in sources:
        return "E_HEADER_DECL_CONFLICT"
    return "E_DOC_DECL_CONFLICT"


def _final_code(source: str) -> str:
    return {
        "bom": "E_BOM_DECL_CONFLICT",
        "http_header": "E_HEADER_BYTE_CONFLICT",
        "xml_declaration": "E_DECL_BYTE_CONFLICT",
        "meta_charset": "E_META_BYTE_CONFLICT",
    }.get(source, "E_DECL_BYTE_CONFLICT")


def _add_code(codes: list[str], code: str) -> None:
    if code not in codes:
        codes.append(code)


def _add_unique(target: list[str], message: str) -> None:
    if message not in target:
        target.append(message)


def _statistical_evidence(candidates: list[CandidateResult]) -> Evidence:
    ordered = ranking(candidates)
    note = "候选评分：" + ", ".join(
        f"{item['encoding']}={item['score']:.6f}" for item in ordered
    )
    winner, _ = choose_best(candidates)
    return Evidence(
        source="statistical",
        declared=winner.encoding if winner else None,
        offset=None,
        line=None,
        note=note,
    )


def _warnings_for(
    source: SourceFile,
    method: str,
    error_codes: list[str],
    conflicts: list[str],
) -> list[WarningItem]:
    warnings: list[WarningItem] = []
    for code in error_codes:
        if code in CONFLICT_CODES:
            continue
        warnings.append(
            WarningItem(code, _SEVERITY.get(code, "medium"), ERROR_CODES.get(code, code))
        )
    conflict_code = next(
        (code for code in error_codes if code in CONFLICT_CODES),
        "E_DOC_DECL_CONFLICT",
    )
    if conflicts:
        warnings.append(
            WarningItem(
                conflict_code,
                _SEVERITY.get(conflict_code, "medium"),
                "；".join(conflicts),
            )
        )
    if method == "fallback":
        warnings.append(WarningItem("W_FALLBACK_USED", "low", ERROR_CODES["W_FALLBACK_USED"]))
    if method == "statistical":
        warnings.append(
            WarningItem("W_STATISTICAL_DECISION", "low", ERROR_CODES["W_STATISTICAL_DECISION"])
        )
    if source.sidecar_error:
        warnings.append(
            WarningItem("W_SIDECAR_INVALID", "medium", source.sidecar_error)
        )
    return warnings


def resolve(
    raw: bytes,
    source: SourceFile,
    evidence: list[Evidence],
    candidates: list[CandidateResult],
    config: Config,
) -> tuple[Decision, list[Evidence], list[WarningItem]]:
    """执行 BOM → 头 → 文档声明 → fallback → 统计的裁决。"""
    working = list(evidence)
    error_codes: list[str] = []
    conflicts: list[str] = []
    chosen: str | None = None
    method = "unresolved"
    confidence = 0.10
    reason = ""

    ordered_sources: list[tuple[str, list[Evidence]]] = [
        ("bom", declaration_values(working, "bom")),
        ("http_header", declaration_values(working, "http_header")),
        ("xml_declaration", declaration_values(working, "xml_declaration")),
        ("meta_charset", declaration_values(working, "meta_charset")),
        ("fallback", declaration_values(working, "fallback")),
    ]
    for candidate_method, items in ordered_sources:
        if not items:
            continue
        item = items[0]
        assert item.declared is not None
        if _try_decode(raw, item.declared):
            chosen = canonical_encoding(item.declared)
            method = candidate_method
            confidence = _METHOD_CONFIDENCE[candidate_method]
            reason = f"按优先级采用 {candidate_method} 声明 {item.declared}"
            break
        if candidate_method != "fallback":
            _add_code(error_codes, "E_DECLARATION_UNDECODABLE")
            _add_unique(
                conflicts,
                f"{candidate_method} 声明 {item.declared} 无法严格解码当前字节",
            )

    if chosen is None:
        winner, stat_confidence = choose_best(candidates)
        if winner is not None:
            chosen = winner.encoding
            method = "statistical"
            confidence = stat_confidence
            reason = f"声明均不可用，统计评分选择 {winner.encoding}"
            if confidence < config.minimum_confidence:
                _add_code(error_codes, "E_LOW_CONFIDENCE")
        else:
            chosen = canonical_encoding(config.fallback_encoding)
            method = "unresolved"
            confidence = 0.10
            _add_code(error_codes, "E_UNDECODABLE")
            reason = "无候选编码可通过严格解码，转入替换策略"

    working.append(_statistical_evidence(candidates))

    declared_items = all_declared(working)
    for index, left in enumerate(declared_items):
        for right in declared_items[index + 1 :]:
            if compatible_encoding(left.declared, right.declared):
                continue
            if left.source == right.source:
                code = "E_DOC_DECL_CONFLICT"
                message = (
                    f"{left.source} 内存在不一致的声明 "
                    f"{left.declared} / {right.declared}"
                )
            else:
                code = _pair_code(left.source, right.source)
                message = (
                    f"{left.source} 声明 {left.declared} 与 "
                    f"{right.source} 声明 {right.declared} 不一致"
                )
            _add_code(error_codes, code)
            _add_unique(conflicts, message)
    for item in declared_items:
        if not compatible_encoding(item.declared, chosen):
            code = _final_code(item.source)
            _add_code(error_codes, code)
            _add_unique(
                conflicts,
                f"{item.source} 声明 {item.declared} 与最终决策 {chosen} 不一致",
            )

    if error_codes:
        confidence = round(max(0.05, confidence * 0.95), 6)
    decision = Decision(
        encoding=canonical_encoding(chosen),
        confidence=confidence,
        method=method,
        reason=reason,
        error_codes=error_codes,
        conflicts=conflicts,
    )
    apply_decision_matches(working, decision.encoding)
    warnings = _warnings_for(source, method, error_codes, conflicts)
    return decision, working, warnings
