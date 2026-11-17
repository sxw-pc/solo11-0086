"""两个明确的采集合同：consensus 与 authorized_capture。"""

from __future__ import annotations

from typing import Any

from .assembly_groups import BUDGET_STATUS
from .config import Config
from .models import Combination, GroupResult

COMPLETE = "complete"
AMBIGUOUS = "ambiguous"
INCOMPLETE = "incomplete"


def capture_of(combination: Combination) -> str:
    captures = {item.decl.capture_id for item in combination.fragments}
    return sorted(captures)[0] if len(captures) == 1 else "mixed"


def cross_conflict(left: Combination, right: Combination) -> dict[str, Any] | None:
    """两个完整组合的首个不同实体字节；相同时返回 None。"""
    if left.sha256 == right.sha256:
        return None
    limit = min(len(left.data), len(right.data))
    offset = next(
        (pos for pos in range(limit) if left.data[pos] != right.data[pos]), limit
    )
    return {
        "kind": "combination_conflict",
        "byte_offset": offset,
        "left": {
            "sha256": left.sha256,
            "capture_id": capture_of(left),
            "byte": left.data[offset : offset + 1].hex(),
            "rel_paths": list(left.rel_paths),
        },
        "right": {
            "sha256": right.sha256,
            "capture_id": capture_of(right),
            "byte": right.data[offset : offset + 1].hex(),
            "rel_paths": list(right.rel_paths),
        },
    }


def _selection_conflict(left: Combination, right: Combination) -> dict[str, Any] | None:
    """被排除组合与选定组合的首个不同字节；相同返回 None。"""
    if left.sha256 == right.sha256:
        return None
    limit = min(len(left.data), len(right.data))
    offset = next(
        (pos for pos in range(limit) if left.data[pos] != right.data[pos]), limit
    )
    return {
        "kind": "combination_conflict",
        "byte_offset": offset,
        "excluded": {
            "sha256": left.sha256,
            "capture_id": capture_of(left),
            "byte": left.data[offset : offset + 1].hex(),
            "rel_paths": list(left.rel_paths),
        },
        "selected": {
            "sha256": right.sha256,
            "capture_id": capture_of(right),
            "byte": right.data[offset : offset + 1].hex(),
            "rel_paths": list(right.rel_paths),
        },
    }


def first_combination_conflict(
    combinations: list[Combination],
) -> dict[str, Any] | None:
    ordered = sorted(combinations, key=lambda item: (item.sha256, item.rel_paths))
    for index, left in enumerate(ordered):
        for right in ordered[index + 1 :]:
            conflict = cross_conflict(left, right)
            if conflict is not None:
                return conflict
    return None


def first_group_conflict(groups: list[GroupResult]) -> dict[str, Any] | None:
    for group in groups:
        if group.overlap_conflicts:
            return group.overlap_conflicts[0]
    return None


def _first_different(
    combination: Combination, pool: list[Combination]
) -> Combination | None:
    """在池中找一个字节不同的对照组合，优先字典序最小者。"""
    ordered = sorted(pool, key=lambda item: (item.sha256, item.rel_paths))
    for other in ordered:
        if other.sha256 != combination.sha256:
            return other
    return None


def excluded_rows(
    groups: list[GroupResult], chosen: Combination | None
) -> list[dict[str, Any]]:
    """保留每个被排除组合的覆盖证据与首个冲突字节。

    未选定组合（例如 consensus 拒判）时，以字典序最小的完整组合为参照，
    逐个记录它与参照的首个不同字节，避免只保留一条全局冲突。
    """
    all_combinations = [
        combination for group in groups for combination in group.combinations
    ]
    rows: list[dict[str, Any]] = []
    for group in groups:
        for combination in group.combinations:
            if chosen is not None and combination.sha256 == chosen.sha256:
                continue
            row: dict[str, Any] = {
                "capture_id": group.capture_id,
                "sha256": combination.sha256,
                "reason": (
                    "实体字节与选定组合不同" if chosen is not None else "未选定任何组合"
                ),
                "fragments": list(combination.rel_paths),
                "coverage": [list(item) for item in combination.coverage],
            }
            counterpart = chosen or _first_different(combination, all_combinations)
            if counterpart is not None:
                conflict = _selection_conflict(combination, counterpart)
                if conflict is not None:
                    row["first_conflict"] = conflict
            rows.append(row)
        if group.status != COMPLETE:
            rows.append(
                {
                    "capture_id": group.capture_id,
                    "sha256": None,
                    "reason": group.status,
                    "details": list(group.reasons),
                    "fragments": [item.rel_path for item in group.fragments],
                    "first_conflict": (
                        group.overlap_conflicts[0] if group.overlap_conflicts else None
                    ),
                }
            )
    rows.sort(
        key=lambda item: (
            str(item["capture_id"]),
            str(item["reason"]),
            str(item["sha256"]),
        )
    )
    return rows


def decide_consensus(
    groups: list[GroupResult],
) -> tuple[str, list[str], Combination | None, list[dict[str, Any]], dict[str, Any] | None]:
    reasons = [
        f"捕获组 {group.capture_id} 状态 {group.status}"
        for group in groups
        if group.status != COMPLETE
    ]
    if any(group.status == BUDGET_STATUS for group in groups):
        reasons.append("至少一个捕获组的候选组合超出预算，无法确认唯一实体")
        return BUDGET_STATUS, reasons, None, excluded_rows(groups, None), None
    complete = [group for group in groups if group.status == COMPLETE]
    if not complete:
        return INCOMPLETE, reasons, None, excluded_rows(groups, None), None
    combinations = [
        combination for group in complete for combination in group.combinations
    ]
    shas = {combination.sha256 for combination in combinations}
    if len(shas) != 1:
        reasons.append(f"存在 {len(shas)} 种不同的完整实体字节，consensus 拒判")
        return (
            AMBIGUOUS,
            reasons,
            None,
            excluded_rows(groups, None),
            first_combination_conflict(combinations),
        )
    winner = sorted(combinations, key=lambda item: item.rel_paths)[0]
    return COMPLETE, reasons, winner, excluded_rows(groups, winner), None


def decide_authorized(
    groups: list[GroupResult], config: Config
) -> tuple[str, list[str], Combination | None, list[dict[str, Any]], dict[str, Any] | None]:
    present = {group.capture_id: group for group in groups}
    reasons: list[str] = []
    chosen_group: GroupResult | None = None
    for capture_id in config.assembly_priority_capture_ids:
        group = present.get(capture_id)
        if group is None:
            reasons.append(f"授权捕获组 {capture_id} 不存在，跳过")
            continue
        if group.status != COMPLETE:
            reasons.append(f"授权捕获组 {capture_id} 不完整或不一致（{group.status}），跳过")
            continue
        shas = {combination.sha256 for combination in group.combinations}
        if len(shas) != 1:
            reasons.append(f"授权捕获组 {capture_id} 自身产生多种实体字节，不能作为唯一实体")
            continue
        chosen_group = group
        break
    if chosen_group is None:
        return (
            "authorized_capture_incomplete",
            reasons,
            None,
            excluded_rows(groups, None),
            first_group_conflict(groups),
        )
    winner = chosen_group.combinations[0]
    excluded = excluded_rows(groups, winner)
    for row in excluded:
        if row["sha256"] is None:
            continue
        if row["capture_id"] == chosen_group.capture_id:
            row["reason"] = "同一授权捕获组内与选定组合字节不同"
        else:
            row["reason"] = (
                f"capture_id {row['capture_id']} 不在授权优先级 "
                f"{chosen_group.capture_id} 之前"
            )
    excluded.sort(key=lambda item: (str(item["capture_id"]), str(item["reason"])))
    return COMPLETE, reasons, winner, excluded, None


def decide_contract(
    groups: list[GroupResult], config: Config
) -> tuple[str, list[str], Combination | None, list[dict[str, Any]], dict[str, Any] | None]:
    contract = config.assembly_contract
    if contract == "off":
        return "disabled", ["组装合同未启用"], None, [], None
    if contract == "consensus":
        return decide_consensus(groups)
    if contract == "authorized_capture":
        return decide_authorized(groups, config)
    raise ValueError(f"未知组装合同: {contract}")
