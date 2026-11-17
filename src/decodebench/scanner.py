"""确定性地扫描本地采集响应目录并读取 sidecar。"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import Config
from .models import FragmentDecl, SourceFile

FRAGMENT_FIELDS = (
    "entity_id",
    "capture_id",
    "byte_start",
    "byte_end_inclusive",
    "entity_size",
    "validator",
)


class ScanError(RuntimeError):
    """扫描阶段无法继续的错误。"""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise ScanError(f"无法读取源文件 {path}: {exc}") from exc
    return digest.hexdigest()


def _utc_mtime(path: Path) -> str:
    try:
        stamp = path.stat().st_mtime
    except OSError as exc:
        raise ScanError(f"无法读取文件时间 {path}: {exc}") from exc
    moment = datetime.fromtimestamp(stamp, tz=timezone.utc).replace(microsecond=0)
    return moment.isoformat().replace("+00:00", "Z")


def _looks_like_source(path: Path, extensions: tuple[str, ...]) -> bool:
    return path.is_file() and not path.is_symlink() and path.suffix.lower() in extensions


def _sidecar_candidates(rel_path: str, config: Config) -> list[Path]:
    relative = Path(rel_path)
    names = [relative.name + config.sidecar_suffix]
    stem_name = relative.stem + config.sidecar_suffix
    if stem_name not in names:
        names.append(stem_name)
    directories: list[Path] = []
    if config.sidecar_root is not None:
        directories.extend([config.sidecar_root / relative.parent, config.sidecar_root])
    directories.append(config.scan_root / relative.parent)
    candidates: list[Path] = []
    for directory in directories:
        for name in names:
            candidates.append(directory / name)
    unique: list[Path] = []
    for item in candidates:
        if item not in unique:
            unique.append(item)
    return unique


def _load_sidecar(path: Path) -> tuple[dict[str, Any], str | None]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return {}, f"sidecar 解析失败: {exc}"
    if not isinstance(data, dict):
        return {}, "sidecar 根节点必须是 JSON 对象"
    headers = data.get("headers", {})
    if headers is not None and not isinstance(headers, dict):
        return {}, "sidecar.headers 必须是对象"
    return data, None


def fragment_payload(sidecar: dict[str, Any]) -> dict[str, Any]:
    """把片段字段从 sidecar 顶层或 fragment 子对象中合并出来。"""
    nested = sidecar.get("fragment")
    if isinstance(nested, dict):
        merged = dict(sidecar)
        for key, value in nested.items():
            merged.setdefault(key, value)
        return merged
    return sidecar


def parse_fragment(sidecar: dict[str, Any]) -> tuple[FragmentDecl | None, str | None]:
    """解析 sidecar 中的片段声明；无声明返回 (None, None)。"""
    payload = fragment_payload(sidecar)
    present = [name for name in FRAGMENT_FIELDS if name in payload]
    if not present:
        return None, None
    missing = [name for name in FRAGMENT_FIELDS if name not in payload]
    if missing:
        return None, f"片段声明缺少字段: {', '.join(missing)}"
    strings: dict[str, str] = {}
    for name in ("entity_id", "capture_id", "validator"):
        value = payload[name]
        if not isinstance(value, str) or not value.strip():
            return None, f"片段字段 {name} 必须是非空字符串"
        strings[name] = value.strip()
    numbers: dict[str, int] = {}
    for name in ("byte_start", "byte_end_inclusive", "entity_size"):
        value = payload[name]
        if isinstance(value, bool) or not isinstance(value, int):
            return None, f"片段字段 {name} 必须是整数"
        numbers[name] = value
    return (
        FragmentDecl(
            entity_id=strings["entity_id"],
            capture_id=strings["capture_id"],
            byte_start=numbers["byte_start"],
            byte_end_inclusive=numbers["byte_end_inclusive"],
            entity_size=numbers["entity_size"],
            validator=strings["validator"],
        ),
        None,
    )


def scan(config: Config) -> list[SourceFile]:
    """扫描目录，按 POSIX 相对路径升序返回源文件。"""
    root = config.scan_root
    if not root.is_dir():
        raise ScanError(f"扫描根目录不存在: {root}")
    files: list[Path] = []
    for path in root.rglob("*"):
        if not _looks_like_source(path, config.extensions):
            continue
        try:
            path.resolve().relative_to(config.out_dir)
            continue
        except ValueError:
            pass
        files.append(path)
    files.sort(key=lambda item: item.relative_to(root).as_posix())

    results: list[SourceFile] = []
    for path in files:
        rel_path = path.relative_to(root).as_posix()
        sidecar_path: Path | None = None
        for candidate in _sidecar_candidates(rel_path, config):
            if candidate.is_file():
                sidecar_path = candidate
                break
        sidecar: dict[str, Any] = {}
        sidecar_error: str | None = None
        sidecar_rel: str | None = None
        fragment: FragmentDecl | None = None
        fragment_error: str | None = None
        if sidecar_path is not None:
            sidecar, sidecar_error = _load_sidecar(sidecar_path)
            try:
                sidecar_rel = sidecar_path.resolve().relative_to(
                    config.scan_root.parent
                ).as_posix()
            except ValueError:
                sidecar_rel = sidecar_path.name
            if sidecar_error is None:
                fragment, fragment_error = parse_fragment(sidecar)
        results.append(
            SourceFile(
                rel_path=rel_path,
                path=path,
                size=path.stat().st_size,
                sha256=_sha256(path),
                mtime=_utc_mtime(path),
                sidecar_path=sidecar_path,
                sidecar_rel=sidecar_rel,
                sidecar=sidecar,
                sidecar_error=sidecar_error,
                fragment=fragment,
                fragment_error=fragment_error,
            )
        )
    return results


def _safe_entity_name(entity_id: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", entity_id).strip("._-")
    if not cleaned or cleaned in {".", ".."}:
        cleaned = "entity-" + hashlib.sha256(entity_id.encode("utf-8")).hexdigest()[:12]
    return cleaned[:80]


def formula_entity_rel_path(entity_id: str) -> str:
    """逻辑实体的相对路径；用于转码输出，不写入源目录。"""
    return f"_assembled/{_safe_entity_name(entity_id)}.response"


def assembled_source(
    entity_id: str,
    raw: bytes,
    sha256: str,
    mtime: str,
    sidecar: dict[str, Any],
    sidecar_rel: str | None,
) -> SourceFile:
    """为组装后的完整实体构造内存 SourceFile；path 不接受写入。"""
    return SourceFile(
        rel_path=formula_entity_rel_path(entity_id),
        path=Path(formula_entity_rel_path(entity_id)),
        size=len(raw),
        sha256=sha256,
        mtime=mtime,
        sidecar_path=None,
        sidecar_rel=sidecar_rel,
        sidecar=sidecar,
        sidecar_error=None,
        fragment=None,
        fragment_error=None,
    )
