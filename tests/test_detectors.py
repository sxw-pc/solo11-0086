from __future__ import annotations

import hashlib
from pathlib import Path

from decodebench.detectors import (
    canonical_encoding,
    compatible_encoding,
    decode_sample,
    detect_bom,
    looks_utf16,
)
from decodebench.evidence import collect_evidence
from decodebench.scanner import scan

RESPONSES = Path(__file__).resolve().parents[1] / "fixtures" / "responses"


def test_bom_detection_and_alias_resolution():
    assert detect_bom(b"\xef\xbb\xbfabc")["encoding"] == "utf-8"
    assert detect_bom(b"\xff\xfea\x00")["encoding"] == "utf-16-le"
    assert detect_bom(b"\xfe\xff\x00a")["encoding"] == "utf-16-be"
    assert detect_bom(b"\xff\xfe\x00\x00")["encoding"] == "utf-32-le"
    assert detect_bom(b"plain") is None
    assert canonical_encoding("GBK") == "gb18030"
    assert canonical_encoding("cp1252") == "windows-1252"
    assert canonical_encoding("ISO_8859-1") == "latin-1"
    assert compatible_encoding("gb2312", "gb18030")
    assert compatible_encoding("UTF-16", "utf-16-le")
    assert compatible_encoding("us-ascii", "utf-8")
    assert not compatible_encoding("big5", "gb18030")


def test_strict_decode_metrics_and_utf16_shape():
    gb_bytes = "中文编码证据".encode("gb18030")
    failed = decode_sample(gb_bytes, "utf-8")
    assert failed.success is False
    assert failed.error
    decoded = decode_sample(gb_bytes, "gb18030")
    assert decoded.success is True
    assert decoded.cjk_ratio > 0.5
    assert decoded.replacement_count == 0
    latin = decode_sample("naïve".encode("cp1252"), "utf-8")
    assert latin.success is False
    assert looks_utf16("hello".encode("utf-16-be"))
    assert not looks_utf16(b"plain ascii text")


def test_evidence_extracts_meta_xml_header_and_fallback(make_config, tmp_path):
    config = make_config()
    sources = {item.rel_path: item for item in scan(config)}
    gb = sources["gb18030_with_utf8_meta.html"]
    gb_evidence = collect_evidence(gb, gb.path.read_bytes(), config)
    meta = [item for item in gb_evidence if item.source == "meta_charset"]
    assert len(meta) == 1
    assert meta[0].declared.lower() == "utf-8"
    assert meta[0].line == 2
    assert meta[0].offset is not None
    assert not [item for item in gb_evidence if item.source == "http_header"]
    assert any(item.source == "fallback" for item in gb_evidence)

    utf16le = sources["utf16le_bom.xml"]
    utf16_evidence = collect_evidence(utf16le, utf16le.path.read_bytes(), config)
    assert [item.source for item in utf16_evidence].count("bom") == 1
    header = [item for item in utf16_evidence if item.source == "http_header"]
    assert header[0].declared.lower() == "utf-16le"
    assert utf16le.sidecar_rel.endswith("utf16le_bom.headers.json")

    utf16be = sources["utf16be_decl.xml"]
    be_evidence = collect_evidence(utf16be, utf16be.path.read_bytes(), config)
    declarations = [item for item in be_evidence if item.source == "xml_declaration"]
    assert declarations[0].declared == "UTF-16BE"
    assert declarations[0].line == 1


def test_scanner_is_deterministic_and_reads_same_directory_sidecar(tmp_path, make_config):
    responses = tmp_path / "responses"
    (responses / "nested").mkdir(parents=True)
    (responses / "b.html").write_text("<meta charset=utf-8>", encoding="utf-8")
    (responses / "a.css").write_text("body{}", encoding="utf-8")
    (responses / "ignored.json").write_text("{}", encoding="utf-8")
    (responses / "nested" / "c.htm").write_text("<p>x</p>", encoding="utf-8")
    (responses / "a.css.headers.json").write_text(
        '{"headers":{"Content-Type":"text/css; charset=utf-8"}}',
        encoding="utf-8",
    )
    config = make_config(scan_root=responses)
    first = [item.rel_path for item in scan(config)]
    second = [item.rel_path for item in scan(config)]
    assert first == ["a.css", "b.html", "nested/c.htm"]
    assert first == second
    scanned = scan(config)
    assert scanned[0].sidecar is not None
    assert scanned[0].sidecar_error is None
    assert scanned[0].sha256 == hashlib.sha256(b"body{}").hexdigest()


def test_repository_fixture_set_contains_expected_encoding_matrix():
    names = {path.name for path in RESPONSES.iterdir()}
    assert {
        "utf8_bom.html",
        "utf8_meta.html",
        "gb18030_no_meta.html",
        "gb18030_with_utf8_meta.html",
        "utf16le_bom.xml",
        "utf16be_decl.xml",
        "big5_meta.html",
        "mixed_eol.css",
        "plain_latin.txt",
        "corrupted_replacement.html",
    } <= names
    assert len(list(RESPONSES.iterdir())) == 10
