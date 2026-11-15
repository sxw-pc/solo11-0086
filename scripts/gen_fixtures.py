"""生成完全离线的采集响应 fixture（幂等覆盖，仅用于仓库样本）。"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESPONSES = ROOT / "fixtures" / "responses"
SIDECARS = ROOT / "fixtures" / "sidecars"


def write_bytes(name: str, payload: bytes) -> None:
    path = RESPONSES / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def write_sidecar(name: str, data: dict) -> None:
    path = SIDECARS / name
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    path.write_text(text, encoding="utf-8")


def main() -> None:
    RESPONSES.mkdir(parents=True, exist_ok=True)
    SIDECARS.mkdir(parents=True, exist_ok=True)

    write_bytes(
        "utf8_bom.html",
        b"\xef\xbb\xbf"
        + (
            '<!doctype html>\n<html lang="zh-CN"><head><meta charset="utf-8">'
            "<title>UTF-8 BOM 样本</title></head>\n"
            "<body><p>采集响应 UTF-8 BOM，BOM 优先。</p></body></html>\n"
        ).encode("utf-8"),
    )
    write_bytes(
        "utf8_meta.html",
        (
            '<!doctype html>\n<html lang="zh-CN"><head><meta charset="UTF-8">'
            "<title>UTF-8 声明样本</title></head>\n"
            "<body><p>无 BOM，元数据声明 UTF-8。</p></body></html>\n"
        ).encode("utf-8"),
    )
    write_bytes(
        "gb18030_no_meta.html",
        (
            '<!doctype html>\n<html lang="zh-CN"><head><title>无声明样本</title></head>\n'
            "<body><p>这段中文使用 GB18030 编码，但没有文档声明。</p></body></html>\n"
        ).encode("gb18030"),
    )
    write_bytes(
        "gb18030_with_utf8_meta.html",
        (
            '<!doctype html>\n<html lang="zh-CN"><head><meta charset="utf-8">'
            "<title>声明冲突样本</title></head>\n"
            "<body><p>字节实际为 GB18030，文档却声明 UTF-8。</p></body></html>\n"
        ).encode("gb18030"),
    )
    write_bytes(
        "utf16le_bom.xml",
        b"\xff\xfe"
        + (
            '<?xml version="1.0" encoding="UTF-16"?>\n'
            "<record><title>UTF-16LE 样本</title><note>BOM 优先</note></record>\n"
        ).encode("utf-16-le"),
    )
    write_bytes(
        "utf16be_decl.xml",
        (
            '<?xml version="1.0" encoding="UTF-16BE"?>\n'
            "<record><title>UTF-16BE 声明样本</title></record>\n"
        ).encode("utf-16-be"),
    )
    write_bytes(
        "big5_meta.html",
        (
            '<!doctype html>\n<html lang="zh-Hant"><head><meta charset="big5">'
            "<title>Big5 樣本</title></head>\n"
            "<body><p>這段繁體中文使用 Big5 編碼並自帶聲明。</p></body></html>\n"
        ).encode("big5"),
    )
    write_bytes(
        "mixed_eol.css",
        (
            "/* 采文解码台 mixed EOL 样本 */\r\n"
            ".panel {\r\n  color: #123;\n  border: 1px solid #ccc;\r"
            "  padding: 4px;\r\n}\r\n"
        ).encode("utf-8"),
    )
    write_bytes(
        "plain_latin.txt",
        (
            "Plain Latin sample.\n"
            "The editor noted “naïve café résumé” "
            "and an em dash — all stored in Windows-1252.\n"
            "A second line keeps the evidence readable.\n"
        ).encode("cp1252"),
    )
    replacement = chr(0xFFFD)
    write_bytes(
        "corrupted_replacement.html",
        (
            '<!doctype html>\n<html lang="zh-CN"><head><meta charset="utf-8">'
            "<title>替换字符样本</title></head>\n"
            f"<body><p>记录：{replacement} 与 Ã© 以及 ??? 需要人工复核。</p></body></html>\n"
        ).encode("utf-8"),
    )

    write_sidecar(
        "gb18030_with_utf8_meta.headers.json",
        {
            "status": 200,
            "url": "http://example.invalid/captures/gb-meta-conflict",
            "headers": {"Content-Type": "text/html"},
        },
    )
    write_sidecar(
        "utf16le_bom.headers.json",
        {
            "status": 200,
            "url": "http://example.invalid/captures/utf16le",
            "headers": {"Content-Type": "application/xml; charset=utf-16le"},
        },
    )
    print(f"fixtures generated under {RESPONSES.as_posix()}")
    for path in sorted(RESPONSES.iterdir()):
        print(f"{path.name:34s} {path.stat().st_size:5d} bytes")


if __name__ == "__main__":
    main()
