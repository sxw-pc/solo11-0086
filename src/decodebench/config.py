"""YAML 配置加载、默认值、路径解析与配置指纹。"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from . import RULE_VERSION


class ConfigError(ValueError):
    """配置不可用时抛出的可读错误。"""


DEFAULTS: dict[str, Any] = {
    "scan": {
        "extensions": [".html", ".htm", ".xml", ".txt", ".css"],
        "sidecar_suffix": ".headers.json",
        "sidecar_root": None,
    },
    "output": {
        "dir": "../out",
        "manifest": "manifest.json",
        "reports_dir": "reports",
        "transcode_dir": "transcoded",
        "database": "decodebench.sqlite3",
    },
    "detection": {
        "fallback_encoding": "utf-8",
        "candidate_encodings": [
            "utf-8",
            "gb18030",
            "big5",
            "utf-16-le",
            "utf-16-be",
            "windows-1252",
            "latin-1",
        ],
        "trusted_http_headers": True,
        "minimum_confidence": 0.55,
    },
    "transcode": {"rewrite_declarations": True, "errors": "strict"},
    "mojibake": {"question_run_threshold": 3, "control_ratio_threshold": 0.01},
    "web": {"host": "127.0.0.1", "port": 5017},
    "sharing": {
        "audit_contact": "local-audit@example.invalid",
        "min_group_size": 2,
        "route": "suppress",
        "export_dir": "shared",
    },
}


@dataclass(frozen=True)
class Config:
    config_path: Path
    scan_root: Path
    extensions: tuple[str, ...]
    sidecar_suffix: str
    sidecar_root: Path | None
    out_dir: Path
    manifest_path: Path
    reports_dir: Path
    transcode_dir: Path
    db_path: Path
    fallback_encoding: str
    candidate_encodings: tuple[str, ...]
    trusted_http_headers: bool
    minimum_confidence: float
    rewrite_declarations: bool
    transcode_errors: str
    question_run_threshold: int
    control_ratio_threshold: float
    web_host: str
    web_port: int
    share_audit_contact: str
    share_min_group_size: int
    share_route: str
    export_dir: Path
    raw: dict[str, Any]
    fingerprint: str

    def ensure_directories(self) -> None:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.transcode_dir.mkdir(parents=True, exist_ok=True)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _require(mapping: dict[str, Any], key: str, kind: type, label: str) -> Any:
    value = mapping.get(key)
    if not isinstance(value, kind):
        raise ConfigError(f"{label}.{key} 类型应为 {kind.__name__}")
    return value


def _resolve(base: Path, value: str) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = base / candidate
    return candidate.resolve()


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def load_config(path: str | Path) -> Config:
    config_path = Path(path).resolve()
    if not config_path.is_file():
        raise ConfigError(f"配置文件不存在: {config_path}")
    try:
        loaded = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ConfigError(f"配置读取失败: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ConfigError("配置根节点必须是 YAML 映射")
    raw = _merge(DEFAULTS, loaded)
    scan = _require(raw, "scan", dict, "配置")
    output = _require(raw, "output", dict, "配置")
    detection = _require(raw, "detection", dict, "配置")
    transcode = _require(raw, "transcode", dict, "配置")
    mojibake = _require(raw, "mojibake", dict, "配置")
    web = _require(raw, "web", dict, "配置")
    sharing = _require(raw, "sharing", dict, "配置")

    base = config_path.parent
    root_value = _require(scan, "root", str, "scan")
    scan_root = _resolve(base, root_value)
    if not scan_root.is_dir():
        raise ConfigError(f"扫描目录不存在: {scan_root}")

    extensions = scan.get("extensions")
    if not isinstance(extensions, list) or not extensions:
        raise ConfigError("scan.extensions 必须是非空列表")
    normalized_extensions: list[str] = []
    for item in extensions:
        if not isinstance(item, str) or not item.startswith("."):
            raise ConfigError("scan.extensions 的每一项都必须以点号开头")
        normalized_extensions.append(item.lower())

    out_value = _require(output, "dir", str, "output")
    out_dir = _resolve(base, out_value)
    manifest_name = _require(output, "manifest", str, "output")
    reports_name = _require(output, "reports_dir", str, "output")
    transcode_name = _require(output, "transcode_dir", str, "output")
    database_name = _require(output, "database", str, "output")
    manifest_path = _resolve(base, str(Path(out_value) / manifest_name))
    reports_dir = _resolve(base, str(Path(out_value) / reports_name))
    transcode_dir = _resolve(base, str(Path(out_value) / transcode_name))
    db_path = _resolve(base, str(Path(out_value) / database_name))
    if out_dir == scan_root or scan_root in out_dir.parents:
        raise ConfigError("输出目录不得位于扫描源目录内，以保护源文件")
    if transcode_dir == scan_root or scan_root in transcode_dir.parents:
        raise ConfigError("转码目录不得位于扫描源目录内，以保护源文件")
    if manifest_path == scan_root or reports_dir == scan_root:
        raise ConfigError("报告与清单不得写入扫描源目录")

    share_contact = sharing.get("audit_contact")
    if not isinstance(share_contact, str) or not share_contact.strip():
        raise ConfigError("sharing.audit_contact 必须是非空字符串")
    share_min_group = sharing.get("min_group_size")
    if not isinstance(share_min_group, int) or share_min_group < 2:
        raise ConfigError("sharing.min_group_size 必须是 >=2 的整数")
    share_route = sharing.get("route")
    if share_route not in {"suppress", "interval"}:
        raise ConfigError("sharing.route 只能是 suppress 或 interval")
    export_name = _require(sharing, "export_dir", str, "sharing")
    export_dir = _resolve(base, str(Path(out_value) / export_name))
    if export_dir == scan_root or scan_root in export_dir.parents:
        raise ConfigError("共享导出目录不得位于扫描源目录内，以保护源文件")

    sidecar_root_value = scan.get("sidecar_root")
    sidecar_root: Path | None = None
    if sidecar_root_value is not None:
        if not isinstance(sidecar_root_value, str) or not sidecar_root_value:
            raise ConfigError("scan.sidecar_root 必须是非空字符串或 null")
        sidecar_root = _resolve(base, sidecar_root_value)
        if not sidecar_root.is_dir():
            raise ConfigError(f"sidecar 目录不存在: {sidecar_root}")

    fallback = detection.get("fallback_encoding")
    if not isinstance(fallback, str) or not fallback.strip():
        raise ConfigError("detection.fallback_encoding 必须是非空字符串")
    candidates = detection.get("candidate_encodings")
    if not isinstance(candidates, list) or not candidates:
        raise ConfigError("detection.candidate_encodings 必须是非空列表")
    if not all(isinstance(item, str) and item.strip() for item in candidates):
        raise ConfigError("候选编码必须是非空字符串")
    minimum = detection.get("minimum_confidence")
    if not isinstance(minimum, (int, float)) or not 0 <= float(minimum) <= 1:
        raise ConfigError("detection.minimum_confidence 必须在 0 到 1 之间")
    trusted = detection.get("trusted_http_headers")
    if not isinstance(trusted, bool):
        raise ConfigError("detection.trusted_http_headers 必须是布尔值")
    errors = transcode.get("errors")
    if errors not in {"strict", "replace"}:
        raise ConfigError("transcode.errors 只能是 strict 或 replace")
    rewrite = transcode.get("rewrite_declarations")
    if not isinstance(rewrite, bool):
        raise ConfigError("transcode.rewrite_declarations 必须是布尔值")
    qr_threshold = mojibake.get("question_run_threshold")
    cr_threshold = mojibake.get("control_ratio_threshold")
    if not isinstance(qr_threshold, int) or qr_threshold < 2:
        raise ConfigError("mojibake.question_run_threshold 必须是 >=2 的整数")
    if not isinstance(cr_threshold, (int, float)) or not 0 <= float(cr_threshold) <= 1:
        raise ConfigError("mojibake.control_ratio_threshold 必须在 0 到 1 之间")
    host = web.get("host")
    port = web.get("port")
    if not isinstance(host, str) or not _is_loopback(host):
        raise ConfigError("web.host 必须是回环地址，复核台拒绝对外监听")
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ConfigError("web.port 必须是 1-65535 的整数")
    suffix = scan.get("sidecar_suffix")
    if not isinstance(suffix, str) or not suffix:
        raise ConfigError("scan.sidecar_suffix 必须是非空字符串")

    fingerprint_source = json.dumps(
        {"config": raw, "rule": RULE_VERSION},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    fingerprint = hashlib.sha256(fingerprint_source).hexdigest()

    return Config(
        config_path=config_path,
        scan_root=scan_root,
        extensions=tuple(dict.fromkeys(normalized_extensions)),
        sidecar_suffix=suffix,
        sidecar_root=sidecar_root,
        out_dir=out_dir,
        manifest_path=manifest_path,
        reports_dir=reports_dir,
        transcode_dir=transcode_dir,
        db_path=db_path,
        fallback_encoding=fallback,
        candidate_encodings=tuple(dict.fromkeys(candidates)),
        trusted_http_headers=trusted,
        minimum_confidence=float(minimum),
        rewrite_declarations=rewrite,
        transcode_errors=errors,
        question_run_threshold=qr_threshold,
        control_ratio_threshold=float(cr_threshold),
        web_host=host,
        web_port=port,
        share_audit_contact=share_contact,
        share_min_group_size=share_min_group,
        share_route=share_route,
        export_dir=export_dir,
        raw=raw,
        fingerprint=fingerprint,
    )
