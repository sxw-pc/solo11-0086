"""仅在可信 sidecar 明确声明 Content-Encoding: gzip 时离线解封装。

压缩实体可能包含串接的多个 gzip member。本模块提供两条有明确授权的归档
路线：``strict`` 只做整体验收，任一步失败都不发布正文；``verified_prefix``
在整体失败时只把此前完整 member 的正文交给调用方归档为 partial UTF-8 产物。
两条路线都不会把失败 member 的解压字节混入输出。
"""

from __future__ import annotations

from .config import Config
from .gzip_members import GzipScan, scan_gzip_entity
from .models import DecompressResult, SourceFile
from .util import sha256_hex

ROUTES = frozenset({"strict", "verified_prefix"})
STATUS_NONE = "none"
STATUS_COMPLETE = "complete"
STATUS_STRICT_FAILED = "strict_failed"
STATUS_PARTIAL_PREFIX = "verified_prefix"


def declared_gzip(source: SourceFile) -> tuple[bool, str | None, str | None]:
    """返回 (是否声明 gzip, 声明原文, 声明错误)。

    只有在可信 sidecar 中存在 ``Content-Encoding`` 且取值是单一 gzip（或
    ``x-gzip``）时才为真。sidecar 自身解析失败不会被误当成 gzip 声明。
    """
    raw = source.content_encoding_raw
    error = source.content_encoding_error
    if error:
        # 明确声明了不受支持/多个取值的 Content-Encoding：必须按失败处理。
        return True, raw, error
    if raw is None:
        return False, None, None
    return True, raw, None


def passthrough(raw: bytes, source: SourceFile) -> DecompressResult:
    """无 gzip 声明的旧样本：正文即原字节，沿用既有字节流程。"""
    return DecompressResult(
        status=STATUS_NONE,
        success=True,
        declared=None,
        reason="sidecar 未声明 Content-Encoding: gzip，按原字节流程处理",
        entity_sha256=source.sha256,
        entity_size=len(raw),
        decoded_sha256=source.sha256,
        decoded_size=len(raw),
        published_body=True,
        partial_prefix=False,
        members=[],
        verified_members=0,
        failure=None,
        limits={},
        body=raw,
    )


def _limits(config: Config) -> dict[str, object]:
    return {
        "max_members": config.gzip_max_members,
        "entity_max_bytes": config.entity_max_bytes,
        "inflate_max_bytes": config.inflate_max_bytes,
        "max_expansion_ratio": config.max_expansion_ratio,
    }


def _scan(raw: bytes, source: SourceFile, config: Config) -> GzipScan:
    return scan_gzip_entity(
        raw,
        max_members=config.gzip_max_members,
        entity_max_bytes=config.entity_max_bytes,
        inflate_max_bytes=config.inflate_max_bytes,
        max_expansion_ratio=config.max_expansion_ratio,
    )


def _declaration_failure(source: SourceFile) -> DecompressResult:
    return DecompressResult(
        status=STATUS_STRICT_FAILED,
        success=False,
        declared=source.content_encoding_raw,
        reason="sidecar 的 Content-Encoding 声明不可用，按失败处理",
        entity_sha256=source.sha256,
        entity_size=source.size,
        decoded_sha256=None,
        decoded_size=0,
        published_body=False,
        partial_prefix=False,
        members=[],
        verified_members=0,
        failure={
            "code": "E_CONTENT_ENCODING_INVALID",
            "message": source.content_encoding_error,
            "member_index": None,
            "offset": None,
            "detail_offset": None,
        },
        limits={},
    )


def decompress(
    source: SourceFile, raw: bytes, config: Config, route: str | None = None
) -> DecompressResult:
    """按声明与 route 解封装实体；无声明时返回 passthrough。"""
    declared, raw_value, error = declared_gzip(source)
    if not config.content_encoding_enabled or not declared:
        return passthrough(raw, source)
    if error:
        return _declaration_failure(source)
    chosen_route = route or config.content_encoding_route
    if chosen_route not in ROUTES:
        raise ValueError(f"未知的 Content-Encoding 归档路线: {chosen_route}")
    scan = _scan(raw, source, config)
    limits = _limits(config)
    if scan.complete:
        return DecompressResult(
            status=STATUS_COMPLETE,
            success=True,
            declared=raw_value,
            reason=f"gzip 实体全部 {len(scan.members)} 个 member 通过验收",
            entity_sha256=source.sha256,
            entity_size=len(raw),
            decoded_sha256=sha256_hex(scan.verified_body),
            decoded_size=len(scan.verified_body),
            published_body=True,
            partial_prefix=False,
            members=[item.to_dict() for item in scan.members],
            verified_members=scan.verified_members,
            failure=None,
            limits=limits,
            body=scan.verified_body,
        )
    # 空的前缀没有可归档正文，也没有可裁决的字符集证据，按严格失败处理。
    prefix_ok = (
        chosen_route == "verified_prefix"
        and scan.verified_members > 0
        and len(scan.verified_body) > 0
    )
    status = STATUS_PARTIAL_PREFIX if prefix_ok else STATUS_STRICT_FAILED
    failure = scan.failure or {}
    reason = (
        f"gzip 实体在 member {failure.get('member_index')} 失败（{failure.get('code')}），"
        + ("仅发布已验证前缀正文" if prefix_ok else "不发布正文")
    )
    return DecompressResult(
        status=status,
        success=False,
        declared=raw_value,
        reason=reason,
        entity_sha256=source.sha256,
        entity_size=len(raw),
        decoded_sha256=sha256_hex(scan.verified_body) if prefix_ok else None,
        decoded_size=len(scan.verified_body) if prefix_ok else 0,
        published_body=False,
        partial_prefix=prefix_ok,
        members=[item.to_dict() for item in scan.members],
        verified_members=scan.verified_members,
        failure=failure,
        limits=limits,
        body=scan.verified_body if prefix_ok else None,
    )


def failure_warning_code(result: DecompressResult) -> str:
    """整体失败时的稳定警告码；上限类失败统一为膨胀限制码。"""
    detail = str(result.failure.get("code")) if result.failure else ""
    if detail in {"E_GZIP_INFLATE_LIMIT", "E_GZIP_RATIO_LIMIT", "E_GZIP_ENTITY_LIMIT"}:
        return "E_GZIP_EXPANSION_LIMIT"
    return detail or "E_UNDECODABLE"


def failure_message(result: DecompressResult) -> str:
    detail = result.failure or {}
    return f"{detail.get('code', 'E_GZIP_UNKNOWN')}: {detail.get('message', result.reason)}"
