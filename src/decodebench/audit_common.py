"""事后审计的共享常量、分层抽样与保守上界。

抽样单位是一个 ``rel_path`` 对应的已交付文件；入样概率在计划构造时一次
冻结，后续标签校验只读该计划，绝不事后调整。
"""

from __future__ import annotations

import hashlib
import json
import math
import random
from typing import Any

from .manifest import AUDIT_FRAME_SCHEMA, RISK_LEVELS

PLAN_SCHEMA = "audit-plan/1.0"
LABEL_SCHEMA = "audit-label/1.0"
ESTIMATE_SCHEMA = "audit-estimate/1.0"
TAG_LABELS = ("correct", "wrong", "undecidable")
DEFAULT_THRESHOLDS = {"files": 0.10, "bytes": 0.10}
DEFAULT_CONFIDENCE = 0.95


class AuditError(ValueError):
    """抽样框、抽样计划或人工标签不可用于本轮审计。"""


def digest(payload: dict[str, Any]) -> str:
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _allocate(populations: dict[str, int], budget: int) -> tuple[dict[str, int], bool]:
    """先给每个非空层 1 份，余量按人口比例分配；预算不足时部分层为 0。"""
    order = {level: index for index, level in enumerate(RISK_LEVELS)}
    names = sorted(populations, key=lambda level: order[level])
    budget = max(0, min(int(budget), sum(populations.values())))
    alloc = {level: 0 for level in names}
    if budget < len(names):
        ranked = sorted(names, key=lambda item: (-populations[item], order[item]))
        for level in ranked[:budget]:
            alloc[level] = 1
        return alloc, False
    for level in names:
        alloc[level] = 1
    remaining = budget - len(names)
    while remaining > 0:
        open_levels = [level for level in names if alloc[level] < populations[level]]
        if not open_levels:
            break
        weight = sum(populations[level] for level in open_levels)
        granted = 0
        fractions: dict[str, float] = {}
        for level in open_levels:
            exact = remaining * populations[level] / weight
            add = min(int(exact), populations[level] - alloc[level])
            alloc[level] += add
            granted += add
            fractions[level] = exact - int(exact)
        remaining -= granted
        if granted == 0:
            pick = max(open_levels, key=lambda item: (fractions[item], -order[item]))
            alloc[pick] += 1
            remaining -= 1
    return alloc, True


def build_audit_plan(
    frame: dict[str, Any], *, budget: int, seed: int | str = 0
) -> dict[str, Any]:
    if frame.get("schema_version") != AUDIT_FRAME_SCHEMA:
        raise AuditError("抽样框 schema 不受支持")
    verify_frame(frame)
    if not isinstance(budget, int) or budget < 0:
        raise AuditError("预算必须是非负整数")
    grouped: dict[str, list[dict[str, Any]]] = {level: [] for level in RISK_LEVELS}
    for unit in frame["delivered_files"]:
        grouped[str(unit["risk_level"])].append(unit)
    populations = {level: len(rows) for level, rows in grouped.items() if rows}
    alloc, enough = _allocate(populations, budget)
    rng = random.Random(seed)
    strata: list[dict[str, Any]] = []
    units: list[dict[str, Any]] = []
    for level in RISK_LEVELS:
        population = populations.get(level, 0)
        if population == 0:
            continue
        size = alloc.get(level, 0)
        pool = sorted(grouped[level], key=lambda row: str(row["rel_path"]))
        chosen = sorted(str(row["rel_path"]) for row in rng.sample(pool, size))
        probability = size / population
        units.extend(
            {
                "rel_path": unit["rel_path"],
                "risk_level": level,
                "source_sha256": unit["source_sha256"],
                "output_sha256": unit["output_sha256"],
                "output_bytes": int(unit["output_bytes"]),
                "output_rel_path": unit["output_rel_path"],
                "stratum_population": population,
                "stratum_sample_size": size,
                "inclusion_probability": probability,
                "sampled": str(unit["rel_path"]) in set(chosen),
            }
            for unit in pool
        )
        strata.append(
            {
                "risk_level": level,
                "population": population,
                "sample_size": size,
                "inclusion_probability": probability,
                "sampled_paths": chosen,
            }
        )
    body: dict[str, Any] = {
        "schema_version": PLAN_SCHEMA,
        "kind": "postdelivery_audit_plan",
        "batch_id": frame["batch_id"],
        "batch_key": frame["batch_key"],
        "frame_digest": frame["frame_digest"],
        "seed": seed,
        "budget": budget,
        "design": "stratified_srs_without_replacement",
        "strata_by": "risk_level",
        "estimable": enough,
        "blocking_reason": None
        if enough
        else "budget_lt_nonempty_strata: 预算不足以让每个非空风险层都有正入样概率",
        "strata": strata,
        "units": sorted(units, key=lambda row: str(row["rel_path"])),
        "sample": sorted(
            (
                {key: value for key, value in unit.items() if key != "sampled"}
                for unit in units
                if unit["sampled"]
            ),
            key=lambda row: str(row["rel_path"]),
        ),
    }
    body["plan_digest"] = digest(body)
    return body


def _log_comb(n: int, k: int) -> float:
    return math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)


def prob_at_most(y: int, wrong: int, population: int, size: int) -> float:
    """超几何分布 P(X <= y)，X 为样本中错误文件数。"""
    good = population - wrong
    terms = [
        _log_comb(wrong, observed)
        + _log_comb(good, size - observed)
        - _log_comb(population, size)
        for observed in range(min(y, size, wrong) + 1)
        if size - observed <= good and size - observed >= 0
    ]
    if not terms:
        return 0.0
    peak = max(terms)
    return math.exp(peak) * sum(math.exp(value - peak) for value in terms)


def upper_wrong_count(observed: int, size: int, population: int, alpha: float) -> int:
    """SRSWOR 下错误文件数的保守单侧上界。"""
    if size <= 0:
        return population
    if size >= population:
        return observed
    low, high = observed, population
    while low < high:
        middle = (low + high + 1) // 2
        if prob_at_most(observed, middle, population, size) >= alpha:
            low = middle
        else:
            high = middle - 1
    return low


def verify_frame(frame: dict[str, Any]) -> None:
    """拒绝被事后改写的抽样框。"""
    if frame.get("schema_version") != AUDIT_FRAME_SCHEMA:
        raise AuditError("抽样框 schema 不受支持")
    body = {key: value for key, value in frame.items() if key != "frame_digest"}
    if digest(body) != frame.get("frame_digest"):
        raise AuditError("抽样框摘要与内容不一致")


def stratum_bound(
    population: int,
    sample_size: int,
    members: list[dict[str, Any]],
    delivered: list[dict[str, Any]],
    level: str,
    alpha: float,
) -> dict[str, Any]:
    """单层错误文件数上界与按输出字节降序分配的字节暴露上界。

    把样本中所有“未确认 correct”的文件（wrong、undecidable、未回应、输出
    缺失）统一视为可能错误，用超几何单侧上界约束总体非 correct 文件数，
    因此不会把未审或不可判文件伪造成零错误。
    """
    wrong = [row for row in members if row["status"] == "wrong"]
    correct = [row for row in members if row["status"] == "correct"]
    non_correct = len(members) - len(correct)
    confirmed = sum(int(row["output_bytes"]) for row in wrong)
    if sample_size <= 0:
        upper, method = population, "empty_sample_full_stratum_upper"
    else:
        upper = upper_wrong_count(non_correct, sample_size, population, alpha)
        method = "hypergeometric_on_non_correct"
    allowance = max(0, upper - len(wrong))
    known = {str(row["rel_path"]) for row in wrong + correct}
    pool = [
        row
        for row in delivered
        if str(row["risk_level"]) == level and str(row["rel_path"]) not in known
    ]
    pool.sort(key=lambda row: (-int(row["output_bytes"]), str(row["rel_path"])))
    extra = sum(int(row["output_bytes"]) for row in pool[:allowance])
    stratum_bytes = sum(
        int(row["output_bytes"]) for row in delivered if str(row["risk_level"]) == level
    )
    return {
        "responded": len(wrong) + len(correct),
        "observed_wrong": len(wrong),
        "confirmed_wrong_bytes": confirmed,
        "non_informative": non_correct - len(wrong),
        "upper_wrong_files_95": upper,
        "upper_exposed_bytes_95": min(confirmed + extra, stratum_bytes),
        "file_upper_method": method,
        "byte_upper_method": "largest_output_bytes_within_file_count_bound",
        "sample_size": sample_size,
    }
