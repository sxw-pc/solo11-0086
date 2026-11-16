"""逐 member 校验 gzip 实体的头、deflate 流、尾、CRC 与 ISIZE。

只接收已落盘字节，绝不联网，也不从压缩字节猜字符集。每个 gzip member 必须
独立通过全部校验；失败 member 的解压结果被丢弃，只有此前的完整 member 正文
可作为“已验证前缀”。
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import asdict, dataclass

GZIP_MAGIC = b"\x1f\x8b"
DEFLATE_METHOD = 8
FHCRC = 0x02
FEXTRA = 0x04
FNAME = 0x08
FCOMMENT = 0x10
FRESERVED = 0xE0
HEADER_FIXED = 10
TRAILER_LEN = 8


class GzipFailure(Exception):
    """在指定实体位置发现的 member 失败。"""

    def __init__(self, code: str, message: str, offset: int, detail: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.offset = offset
        self.detail_offset = offset if detail is None else detail


@dataclass
class MemberResult:
    index: int
    status: str
    start_offset: int
    header_length: int | None = None
    deflate_offset: int | None = None
    deflate_length: int | None = None
    trailer_offset: int | None = None
    end_offset: int | None = None
    compressed_bytes: int | None = None
    inflated_bytes: int = 0
    crc32: int | None = None
    isize: int | None = None
    crc_ok: bool | None = None
    isize_ok: bool | None = None
    error_code: str | None = None
    error_message: str | None = None
    error_offset: int | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass
class GzipScan:
    members: list[MemberResult]
    verified_body: bytes
    complete: bool
    failure: dict[str, object] | None

    @property
    def verified_members(self) -> int:
        return sum(1 for item in self.members if item.status == "verified")


def _parse_header(entity: bytes, start: int, index: int) -> int:
    """返回 deflate 流起点；头不完整或不合法时抛出 GzipFailure。"""
    remaining = len(entity) - start
    if remaining < 2 or entity[start : start + 2] != GZIP_MAGIC:
        if index == 0:
            raise GzipFailure("E_GZIP_NOT_GZIP", "实体开头不是 gzip magic", start)
        raise GzipFailure(
            "E_GZIP_MEMBER_BOUNDARY",
            f"第 {index} 个 member 边界不可信：后续字节不是 gzip magic",
            start,
        )
    if remaining < HEADER_FIXED:
        raise GzipFailure(
            "E_GZIP_HEADER_INVALID",
            f"第 {index} 个 member 固定头不足 {HEADER_FIXED} 字节",
            start,
            len(entity),
        )
    method, flags = entity[start + 2], entity[start + 3]
    if method != DEFLATE_METHOD or flags & FRESERVED:
        raise GzipFailure(
            "E_GZIP_HEADER_INVALID",
            f"第 {index} 个 member 压缩方法/flag 非法",
            start,
        )
    position = start + HEADER_FIXED
    if flags & FEXTRA:
        if position + 2 > len(entity):
            raise GzipFailure("E_GZIP_HEADER_INVALID", "FEXTRA 长度缺失", start, position)
        extra_length = struct.unpack_from("<H", entity, position)[0]
        position += 2 + extra_length
        if position > len(entity):
            raise GzipFailure("E_GZIP_HEADER_INVALID", "FEXTRA 数据被截断", start, position)
    for flag, label in ((FNAME, "FNAME"), (FCOMMENT, "FCOMMENT")):
        if not flags & flag:
            continue
        terminator = entity.find(b"\x00", position)
        if terminator < 0:
            raise GzipFailure(
                "E_GZIP_HEADER_INVALID", f"{label} 缺少 NUL 终止符", start, position
            )
        position = terminator + 1
    if flags & FHCRC:
        if position + 2 > len(entity):
            raise GzipFailure("E_GZIP_HEADER_INVALID", "FHCRC 被截断", start, position)
        stored = struct.unpack_from("<H", entity, position)[0]
        if stored != zlib.crc32(entity[start:position]) & 0xFFFF:
            raise GzipFailure("E_GZIP_HEADER_CRC_MISMATCH", "FHCRC 不匹配", start, position)
        position += 2
    return position


def _inflate(
    entity: bytes, member: MemberResult, cap: int, cap_code: str, cap_message: str
) -> tuple[bytes, int]:
    """有界解压当前 member；返回正文与尾起点。"""
    assert member.deflate_offset is not None
    inflater = zlib.decompressobj(-zlib.MAX_WBITS)
    pending: bytes | memoryview = memoryview(entity)[member.deflate_offset :]
    chunks: list[bytes] = []
    produced = 0
    while not inflater.eof:
        step = 1 if produced >= cap else min(65536, cap - produced + 1)
        try:
            piece = inflater.decompress(pending, step)
        except zlib.error as exc:
            raise GzipFailure(
                "E_GZIP_DECOMPRESS_ERROR",
                f"第 {member.index} 个 member 的 deflate 流损坏: {exc}",
                member.start_offset,
                member.deflate_offset,
            ) from exc
        if piece:
            chunks.append(piece)
            produced += len(piece)
        if produced > cap:
            raise GzipFailure(cap_code, cap_message, member.start_offset, member.deflate_offset)
        if not inflater.eof:
            if not inflater.unconsumed_tail:
                raise GzipFailure(
                    "E_GZIP_MEMBER_TRUNCATED",
                    f"第 {member.index} 个 member 的 deflate 流被截断",
                    member.start_offset,
                    len(entity),
                )
            pending = inflater.unconsumed_tail
    body = b"".join(chunks)
    trailer_offset = len(entity) - len(inflater.unused_data)
    member.deflate_length = trailer_offset - member.deflate_offset
    member.trailer_offset = trailer_offset
    member.inflated_bytes = produced
    return body, trailer_offset


def _failure(
    code: str, message: str, offset: int, detail: int | None, index: int | None
) -> dict[str, object]:
    return {
        "code": code,
        "message": message,
        "member_index": index,
        "offset": offset,
        "detail_offset": offset if detail is None else detail,
    }


def scan_gzip_entity(
    entity: bytes,
    *,
    max_members: int,
    entity_max_bytes: int,
    inflate_max_bytes: int,
    max_expansion_ratio: float,
) -> GzipScan:
    """扫描串接 gzip member；只有全部成员通过才算完整。"""
    if len(entity) > entity_max_bytes:
        message = f"实体 {len(entity)} 字节超过解封装前上限 {entity_max_bytes}；未开始解压"
        return GzipScan([], b"", False, _failure("E_GZIP_ENTITY_LIMIT", message, 0, None, None))
    if not entity:
        return GzipScan(
            [], b"", False,
            _failure("E_GZIP_NOT_GZIP", "sidecar 声明 gzip，但实体为空", 0, None, None),
        )
    ratio_cap = int(len(entity) * max_expansion_ratio)
    if ratio_cap < 1:
        message = (
            f"实体 {len(entity)} 字节在膨胀比上限 {max_expansion_ratio} 下"
            "可用正文预算为 0；未开始解压"
        )
        return GzipScan([], b"", False, _failure("E_GZIP_RATIO_LIMIT", message, 0, None, None))
    parts: list[bytes] = []
    members: list[MemberResult] = []
    produced_total = 0
    position = 0
    while position < len(entity):
        if len(members) >= max_members:
            message = f"member 数量超过上限 {max_members}"
            return GzipScan(
                members, b"".join(parts), False,
                _failure("E_GZIP_MEMBER_LIMIT", message, position, None, None),
            )
        member = MemberResult(index=len(members), status="verified", start_offset=position)
        members.append(member)
        try:
            header_end = _parse_header(entity, position, member.index)
            member.header_length = header_end - position
            member.deflate_offset = header_end
            inflate_left = inflate_max_bytes - produced_total
            ratio_left = ratio_cap - produced_total
            budget = min(inflate_left, ratio_left)
            ratio_binding = ratio_left <= inflate_left
            if budget <= 0:
                if ratio_binding:
                    code = "E_GZIP_RATIO_LIMIT"
                    message = f"解压膨胀比达到上限 {max_expansion_ratio}"
                else:
                    code = "E_GZIP_INFLATE_LIMIT"
                    message = f"解压后总字节达到上限 {inflate_max_bytes}"
                raise GzipFailure(code, message, position, header_end)
            if ratio_binding:
                cap_code = "E_GZIP_RATIO_LIMIT"
                cap_message = f"解压膨胀比超过上限 {max_expansion_ratio}"
            else:
                cap_code = "E_GZIP_INFLATE_LIMIT"
                cap_message = f"解压后总字节超过上限 {inflate_max_bytes}"
            body, trailer_offset = _inflate(entity, member, budget, cap_code, cap_message)
            if trailer_offset + TRAILER_LEN > len(entity):
                raise GzipFailure(
                    "E_GZIP_TRAILER_MISSING",
                    f"第 {member.index} 个 member 的 8 字节尾被截断",
                    position,
                    trailer_offset,
                )
            crc32, isize = struct.unpack_from("<II", entity, trailer_offset)
            member.crc32 = crc32
            member.isize = isize
            member.crc_ok = crc32 == (zlib.crc32(body) & 0xFFFFFFFF)
            member.isize_ok = isize == (len(body) & 0xFFFFFFFF)
            if not member.crc_ok:
                raise GzipFailure(
                    "E_GZIP_CRC_MISMATCH",
                    f"第 {member.index} 个 member 的 CRC32 不匹配",
                    position,
                    trailer_offset,
                )
            if not member.isize_ok:
                raise GzipFailure(
                    "E_GZIP_ISIZE_MISMATCH",
                    f"第 {member.index} 个 member 的 ISIZE 与解压长度不匹配",
                    position,
                    trailer_offset + 4,
                )
            member.end_offset = trailer_offset + TRAILER_LEN
            member.compressed_bytes = member.end_offset - position
            parts.append(body)
            produced_total += len(body)
            position = member.end_offset
        except GzipFailure as exc:
            member.status = "failed"
            member.error_code = exc.code
            member.error_message = exc.message
            member.error_offset = exc.detail_offset
            return GzipScan(
                members,
                b"".join(parts),
                False,
                _failure(exc.code, exc.message, exc.offset, exc.detail_offset, member.index),
            )
    return GzipScan(members, b"".join(parts), True, None)
