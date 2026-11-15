from __future__ import annotations

from decodebench.evidence import collect_evidence
from decodebench.resolver import resolve
from decodebench.scanner import scan
from decodebench.scorer import analyze_candidates


def resolve_fixture(config, rel_path):
    source = next(item for item in scan(config) if item.rel_path == rel_path)
    raw = source.path.read_bytes()
    evidence = collect_evidence(source, raw, config)
    candidates = analyze_candidates(raw, config.candidate_encodings)
    decision, resolved_evidence, warnings = resolve(raw, source, evidence, candidates, config)
    return source, raw, decision, resolved_evidence, warnings, candidates


def test_document_declaration_conflict_is_reported(make_config):
    config = make_config()
    _, _, decision, evidence, warnings, _ = resolve_fixture(
        config, "gb18030_with_utf8_meta.html"
    )
    assert decision.encoding == "gb18030"
    assert decision.method == "statistical"
    assert "E_META_BYTE_CONFLICT" in decision.error_codes
    assert "E_DECLARATION_UNDECODABLE" in decision.error_codes
    assert decision.conflicts
    assert 0 < decision.confidence <= 1
    meta = next(item for item in evidence if item.source == "meta_charset")
    assert meta.matches_decision is False
    fallback = next(item for item in evidence if item.source == "fallback")
    assert fallback.matches_decision is False
    statistical = next(item for item in evidence if item.source == "statistical")
    assert statistical.matches_decision is True
    warning_codes = {item.code for item in warnings}
    assert "E_META_BYTE_CONFLICT" in warning_codes
    assert "W_STATISTICAL_DECISION" in warning_codes


def test_bom_beats_header_and_declaration(make_config):
    config = make_config()
    _, raw, decision, evidence, warnings, _ = resolve_fixture(config, "utf16le_bom.xml")
    assert decision.encoding == "utf-16-le"
    assert decision.method == "bom"
    assert decision.confidence > 0.95
    assert not decision.conflicts
    assert not [item for item in warnings if item.code.startswith("E_")]
    bom = next(item for item in evidence if item.source == "bom")
    header = next(item for item in evidence if item.source == "http_header")
    declaration = next(item for item in evidence if item.source == "xml_declaration")
    assert bom.matches_decision is True
    assert header.matches_decision is True
    encoded_value = "UTF-16".encode("utf-16-le")
    assert declaration.offset == raw.find(encoded_value)


def test_utf8_bom_and_meta_declarations(make_config):
    config = make_config()
    _, _, bom_decision, _, _, _ = resolve_fixture(config, "utf8_bom.html")
    assert (bom_decision.encoding, bom_decision.method) == ("utf-8", "bom")
    _, _, meta_decision, meta_evidence, _, _ = resolve_fixture(config, "utf8_meta.html")
    assert (meta_decision.encoding, meta_decision.method) == ("utf-8", "meta_charset")
    meta = next(item for item in meta_evidence if item.source == "meta_charset")
    assert meta.matches_decision is True


def test_xml_declaration_without_bom(make_config):
    config = make_config()
    _, _, decision, evidence, _, candidates = resolve_fixture(config, "utf16be_decl.xml")
    assert decision.encoding == "utf-16-be"
    assert decision.method == "xml_declaration"
    declaration = next(item for item in evidence if item.source == "xml_declaration")
    assert declaration.declared == "UTF-16BE"
    assert declaration.matches_decision is True
    assert any(item.encoding == "utf-16-be" and item.success for item in candidates)


def test_big5_meta_and_latin_fallback_paths(make_config):
    config = make_config()
    _, _, big5_decision, big5_evidence, _, _ = resolve_fixture(config, "big5_meta.html")
    assert big5_decision.encoding == "big5"
    assert big5_decision.method == "meta_charset"
    assert not big5_decision.conflicts
    assert next(
        item for item in big5_evidence if item.source == "meta_charset"
    ).matches_decision is True

    _, _, latin_decision, _, warning_items, _ = resolve_fixture(config, "plain_latin.txt")
    assert latin_decision.encoding == "windows-1252"
    assert latin_decision.method == "statistical"
    assert "W_STATISTICAL_DECISION" in {item.code for item in warning_items}


def test_fallback_method_and_warning(make_config):
    config = make_config()
    _, _, decision, evidence, warnings, _ = resolve_fixture(config, "mixed_eol.css")
    assert decision.encoding == "utf-8"
    assert decision.method == "fallback"
    assert decision.confidence == 0.72
    fallback = next(item for item in evidence if item.source == "fallback")
    assert fallback.matches_decision is True
    assert any(item.code == "W_FALLBACK_USED" for item in warnings)


def test_multiple_meta_declarations_conflict(tmp_path, make_config):
    responses = tmp_path / "responses"
    responses.mkdir()
    (responses / "two_metas.html").write_text(
        '<meta charset="gb18030"><meta charset="big5"><p>ascii</p>',
        encoding="ascii",
    )
    config = make_config(scan_root=responses)
    source = scan(config)[0]
    raw = source.path.read_bytes()
    evidence = collect_evidence(source, raw, config)
    candidates = analyze_candidates(raw, config.candidate_encodings)
    decision, _, _ = resolve(raw, source, evidence, candidates, config)
    assert decision.encoding == "gb18030"
    assert "E_DOC_DECL_CONFLICT" in decision.error_codes
    assert "E_META_BYTE_CONFLICT" in decision.error_codes


def test_invalid_sidecar_produces_warning(tmp_path, make_config):
    responses = tmp_path / "responses"
    responses.mkdir()
    (responses / "sample.html").write_text("<meta charset=utf-8><p>ok</p>", encoding="utf-8")
    (responses / "sample.html.headers.json").write_text("{not valid json", encoding="utf-8")
    config = make_config(scan_root=responses)
    source = scan(config)[0]
    raw = source.path.read_bytes()
    evidence = collect_evidence(source, raw, config)
    candidates = analyze_candidates(raw, config.candidate_encodings)
    decision, _, warnings = resolve(raw, source, evidence, candidates, config)
    assert decision.encoding == "utf-8"
    assert source.sidecar_error
    assert any(item.code == "W_SIDECAR_INVALID" for item in warnings)
