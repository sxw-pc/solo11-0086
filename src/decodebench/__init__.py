"""采文解码台：本地采集响应编码诊断与转码归档工具。"""

__version__ = "0.1.0"
RULE_VERSION = "decodebench-2024.01.1"

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
    "E_304_NOT_STATE_SIDECAR": "304 缺少离线验证合成状态字段",
    "E_304_MALFORMED_STATE": "304 状态 sidecar 结构不符合合同",
    "E_304_NO_CANDIDATE_200": "找不到同资源键、同 Vary 且早于 304 的 200 原件",
    "E_304_VARY_INPUT_MISSING": "304 缺少 Vary 请求输入，无法确认协商变体",
    "E_304_WEAK_VALIDATOR": "只存在弱验证标记（W/），禁止复用正文",
    "E_304_ETAG_MISMATCH": "304 与候选 200 的强 ETag 不一致",
    "E_304_ENTITY_CONFLICT": "多个候选 200 实体摘要矛盾，无法唯一归属",
    "E_304_ORIGINAL_UNREADABLE": "被归属 200 原始实体字节不可读或已损坏",
    "E_304_REFRESHED_UNDECODABLE": "304 更新头部无法严格解码复用字节，拒绝发布",
    "W_304_ATTRIBUTION_REVIEW": "304 无法自动归属，保留证据待人工复核",
    "W_304_FORENSIC_VALIDATION": "304 仅记为验证事件，沿用 200 原始视图",
}

CONFLICT_CODES = frozenset(code for code in ERROR_CODES if code.endswith("CONFLICT"))
