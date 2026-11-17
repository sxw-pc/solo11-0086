"""组装合同配置的校验与覆盖。"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from . import RULE_VERSION

ASSEMBLY_CONTRACTS = ("off", "consensus", "authorized_capture")
ASSEMBLY_DEFAULTS: dict[str, Any] = {
    "contract": "off",
    "priority_capture_ids": [],
    "max_combinations_per_entity": 256,
}


class AssemblyConfigError(ValueError):
    """组装合同配置不可用。"""


def _normalize_contract(value: Any) -> Any:
    """YAML 未加引号的 off 会被解析为 False，这里还原为字符串。"""
    if value is False:
        return "off"
    if value is True:
        return "invalid"
    return value


def validate_assembly(assembly: Any) -> tuple[str, tuple[str, ...], int]:
    if not isinstance(assembly, dict):
        raise AssemblyConfigError("assembly 必须是映射")
    contract = _normalize_contract(assembly.get("contract", "off"))
    if contract not in ASSEMBLY_CONTRACTS:
        raise AssemblyConfigError(
            "assembly.contract 只能是 off、consensus 或 authorized_capture"
        )
    priority_ids = assembly.get("priority_capture_ids", [])
    if not isinstance(priority_ids, list) or not all(
        isinstance(item, str) and item.strip() for item in priority_ids
    ):
        raise AssemblyConfigError("assembly.priority_capture_ids 必须是字符串列表")
    if len(set(priority_ids)) != len(priority_ids):
        raise AssemblyConfigError("assembly.priority_capture_ids 不得重复")
    if contract == "authorized_capture" and not priority_ids:
        raise AssemblyConfigError(
            "assembly.contract=authorized_capture 需要非空 priority_capture_ids"
        )
    max_combinations = assembly.get("max_combinations_per_entity", 256)
    if not isinstance(max_combinations, int) or max_combinations < 1:
        raise AssemblyConfigError(
            "assembly.max_combinations_per_entity 必须是正整数"
        )
    return contract, tuple(priority_ids), max_combinations


def fingerprint(raw: dict[str, Any]) -> str:
    source = json.dumps(
        {"config": raw, "rule": RULE_VERSION},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(source).hexdigest()
