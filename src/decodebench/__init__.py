"""采文解码台：本地采集响应编码诊断与转码归档工具。"""

__version__ = "0.1.0"
RULE_VERSION = "decodebench-2024.02.1"

ERROR_CODES = {
    "E_BOM_DECL_CONFLICT": "BOM 与文档声明不一致",
    "E_HEADER_DECL_CONFLICT": "HTTP 头声明与文档声明不一致",
    "E_DOC_DECL_CONFLICT": "文档内多个编码声明不一致",
    "E_BOM_HEADER_CONFLICT": "BOM 与可信 HTTP 头声明不一致",
    "E_META_BYTE_CONFLICT": "HTML meta 声明与字节统计结果冲突",
    "E_DECL_BYTE_CONFLICT": "XML 声明与字节统计结果冲突",
    "E_HEADER_BYTE_CONFLICT": "可信 HTTP 头声明与字节统计结果冲突",
    "E_DECLARATION_UNDECODABLE": "声明编码无法严格解码当前字节",
    "E_UNDECODABLE": "所有候选编码均无法严格解码",
    "E_LOW_CONFIDENCE": "编码判定置信度低于阈值",
    "W_FALLBACK_USED": "未找到可信声明，使用配置兜底编码",
    "W_STATISTICAL_DECISION": "通过统计评分确定编码",
    "W_SIDECAR_INVALID": "响应头 sidecar 无法读取",
    "W_REPLACEMENT_CHARS": "正文包含 Unicode 替换字符",
    "W_MOJIBAKE_SEQUENCE": "正文包含典型 mojibake 序列",
    "W_CONTROL_CHARS": "正文包含不可打印控制字符",
    "W_QUESTION_RUNS": "正文包含连续问号",
    "W_SURROGATE_TRACE": "正文包含非法代理项痕迹",
    "E_CONTENT_ENCODING_INVALID": "sidecar 的 Content-Encoding 声明不可用",
    "E_GZIP_NOT_GZIP": "声明 gzip，但实体不是 gzip 格式",
    "E_GZIP_MEMBER_BOUNDARY": "gzip member 边界不可信",
    "E_GZIP_HEADER_INVALID": "gzip member 头不合法",
    "E_GZIP_HEADER_CRC_MISMATCH": "gzip member 头 FHCRC 不匹配",
    "E_GZIP_MEMBER_TRUNCATED": "gzip member 正文被截断",
    "E_GZIP_TRAILER_MISSING": "gzip member 尾部不完整",
    "E_GZIP_CRC_MISMATCH": "gzip member CRC32 不匹配",
    "E_GZIP_ISIZE_MISMATCH": "gzip member ISIZE 不匹配",
    "E_GZIP_DECOMPRESS_ERROR": "gzip deflate 流损坏",
    "E_GZIP_MEMBER_LIMIT": "gzip member 数超过上限",
    "E_GZIP_ENTITY_LIMIT": "gzip 实体超过解封装前字节上限",
    "E_GZIP_INFLATE_LIMIT": "gzip 解压后字节超过上限",
    "E_GZIP_RATIO_LIMIT": "gzip 解压膨胀比超过上限",
    "E_GZIP_EXPANSION_LIMIT": "gzip 解封装被上限拒绝，未发布正文",
    "W_GZIP_PARTIAL_PREFIX": "仅归档了已验证的 gzip 前缀正文",
}

CONFLICT_CODES = frozenset(code for code in ERROR_CODES if code.endswith("CONFLICT"))
