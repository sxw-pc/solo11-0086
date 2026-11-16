"""确定性地扫描本地采集响应目录并读取 sidecar。"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import Config
from .evidence import content_encoding_value
from .models import SourceFile


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
        sidecar_sha: str | None = None
        if sidecar_path is not None:
            sidecar_sha = _sha256(sidecar_path)
            sidecar, sidecar_error = _load_sidecar(sidecar_path)
            try:
                sidecar_rel = sidecar_path.resolve().relative_to(
                    config.scan_root.parent
                ).as_posix()
            except ValueError:
                sidecar_rel = sidecar_path.name
        content_raw: str | None = None
        content_error: str | None = None
        if (
            config.content_encoding_enabled
            and config.trusted_http_headers
            and sidecar
            and sidecar_error is None
        ):
            content_raw, content_error = content_encoding_value(sidecar)
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
                sidecar_sha256=sidecar_sha,
                content_encodings=(
                    (content_raw,) if content_raw and not content_error else ()
                ),
                content_encoding_raw=content_raw,
                content_encoding_error=content_error,
            )
        )
    return results
