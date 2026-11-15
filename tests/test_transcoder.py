from __future__ import annotations

import hashlib

from decodebench.scanner import scan
from decodebench.transcoder import rewrite_declarations, transcode


def _source(config, name):
    return next(item for item in scan(config) if item.rel_path == name)


def test_gb18030_transcode_writes_separate_utf8_output(make_config):
    config = make_config()
    source = _source(config, "gb18030_no_meta.html")
    raw = source.path.read_bytes()
    result = transcode(source, raw, "gb18030", config)
    assert result.success is True
    assert result.encoding == "gb18030"
    assert result.output_rel_path == "gb18030_no_meta.html"
    assert result.source_sha256 == source.sha256
    output = config.transcode_dir / result.output_rel_path
    payload = output.read_bytes()
    assert payload.decode("utf-8")
    assert "这段中文使用 GB18030" in payload.decode("utf-8")
    assert hashlib.sha256(payload).hexdigest() == result.output_sha256
    assert source.path.read_bytes() == raw
    assert output != source.path


def test_big5_meta_declaration_rewrite_is_recorded(make_config):
    config = make_config()
    source = _source(config, "big5_meta.html")
    result = transcode(source, source.path.read_bytes(), "big5", config)
    assert result.success is True
    assert len(result.rewrites) == 1
    rewrite = result.rewrites[0]
    assert rewrite["kind"] == "html_meta_charset"
    assert rewrite["original"] == "big5"
    assert rewrite["new"] == "utf-8"
    assert rewrite["line"] == 2
    assert isinstance(rewrite["offset"], int)
    output = (config.transcode_dir / source.rel_path).read_text(encoding="utf-8")
    assert '<meta charset="utf-8">' in output
    assert '"big5"' not in output


def test_utf16_bom_is_removed_and_xml_declaration_rewritten(make_config):
    config = make_config()
    source = _source(config, "utf16le_bom.xml")
    result = transcode(source, source.path.read_bytes(), "utf-16-le", config)
    assert result.success is True
    assert result.bom_removed is True
    assert len(result.rewrites) == 1
    payload = (config.transcode_dir / source.rel_path).read_bytes()
    assert not payload.startswith(b"\xff\xfe")
    assert payload.startswith(b'<?xml version="1.0" encoding="utf-8"?>')
    assert "UTF-16LE 样本" in payload.decode("utf-8")


def test_strict_and_replace_error_policies(tmp_path, make_config):
    responses = tmp_path / "responses"
    responses.mkdir()
    (responses / "bad.txt").write_bytes(b"\xff\xfe\x80")
    strict_config = make_config(scan_root=responses, transcode_errors="strict")
    source = scan(strict_config)[0]
    failed = transcode(source, b"\xff\xfe\x80", "utf-8", strict_config)
    assert failed.success is False
    assert failed.output_rel_path is None
    assert not (strict_config.transcode_dir / "bad.txt").exists()

    replace_config = make_config(scan_root=responses, transcode_errors="replace")
    replaced = transcode(source, b"\xff\xfe\x80", "utf-8", replace_config)
    assert replaced.success is True
    assert replaced.errors == "replace"
    assert replaced.replacement_count == 3
    assert replaced.replacement_used is True
    text = (replace_config.transcode_dir / "bad.txt").read_text(encoding="utf-8")
    assert text == chr(0xFFFD) * 3


def test_rewrite_declaration_limits():
    text = "body{}\r\n"
    assert rewrite_declarations(text, ".css") == (text, [])
    xml = '<?xml version="1.0" encoding="GB18030"?><x/>'
    rewritten, records = rewrite_declarations(xml, ".xml")
    assert 'encoding="utf-8"' in rewritten
    assert records[0]["original"] == "GB18030"
    already = '<?xml version="1.0" encoding="UTF-8"?><x/>'
    assert rewrite_declarations(already, ".xml") == (already, [])
