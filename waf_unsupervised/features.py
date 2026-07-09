from __future__ import annotations

import math
import os
import re
import sys
from collections import Counter
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qsl, unquote, urlparse

import numpy as np
import pandas as pd
from joblib import Parallel, delayed
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import MinMaxScaler

from .whitelist import is_whitelisted_path

# ============================================================
# 1) Rule patterns (regex layer)
# ============================================================

SQL_PATTERNS: List[str] = [
    r"(?i)\bunion\s+select\b",
    r"(?i)\bor\s+1=1\b",
    r"(?i)\band\s+1=1\b",
    r"(?i)\binformation_schema\b",
    r"(?i)\bsleep\s*\(",
    r"(?i)\bbenchmark\s*\(",
    r"(?i)\bselect\b",
    r"(?i)\bunion\b",
    r"(?i)\bdrop\b",
    r"(?i)\binsert\b",
    r"(?i)--|/\*|\*/|'|\"",
]

XSS_PATTERNS: List[str] = [
    r"(?i)<script",
    r"(?i)javascript:",
    r"(?i)onerror\s*=",
    r"(?i)onload\s*=",
    r"(?i)<img[^>]+on\w+\s*=",
    r"(?i)<svg[^>]+on\w+\s*=",
]

TRAVERSAL_PATTERNS: List[str] = [
    r"\.\./",
    r"(?i)\.\.%2f|%2e%2e",
    r"(?i)%252e%252e|%255c",
    r"(?i)/etc/passwd|/windows/win.ini",
]

CMD_PATTERNS: List[str] = [
    r"(?i)(;|\|\||&&)\s*(cat|ls|whoami|id|curl|wget|bash|sh)\b",
    r"(?i)\b(cmd|powershell|bash|sh)\b",
    r"`[^`]+`",
    r"\$\([^)]+\)",
    r"(?i)(?:%0d%0a|%0a%0d)(?:%0d%0a|%0a%0d)+",
    r"(?i)(?:%0a){2,}|(?:%0d){2,}",
    r"(?i)(?:\||%7c)(?:%20|[+\s])*(?:bash|sh|zsh|dash|ksh|pwsh|powershell|cmd|rundll32)\b",
    r"(?i)(?:>|%3e)(?:%20|[+\s])*(?:/tmp\b|%2ftmp|/var\b|%2fvar|/dev/null|%2fdev%2fnull)",
    r"(?i)2%3e%261|2%3e%25261|2>&1|%3e%26|%2526",
    r"(?i)(?:\$\(|%24%28|`)(?:%20|\s)*[\w/\\.-]{1,64}",
    r"(?i)(?:;|%3b)(?:%20|[+\s])*(?:wget|curl|fetch)\b",
]

HTTP_PROTO_PATTERNS: List[str] = [
    r"(?i)visualseawind",
    r"(?i)multipart/form-data[^;\n]*boundary\s*=\s*-[^\s;]+",
    r"(?i)microsoft-atl-native/[\d.]+",
]

# Event-type oriented rule groups, aligned with the list you gave.
EVENT_TYPE_RULE_PATTERNS: Dict[str, List[str]] = {
    "HTTP_Protocol_Validation": [
        r"(?im)^accept\s*:",
        r"(?i)boundary\s*=\s*-[A-Za-z0-9_-]",
        r"(?i)multipart/form-data[^;\n]*boundary\s*=\s*-[^\s;]+",
        r"(?i)microsoft-atl-native/[\d.]+",
        r"(?i)visualseawind",
        r"(?is)/(?:kns-query|query3)\b.*multipart/form-data[^;\n]*boundary\s*=\s*-visualseawind",
        r"(?is)/(?:kns-query|query3)\b.*microsoft-atl-native/[\d.]+",
        r"(?is)microsoft-atl-native/[\d.]+.*(?:visualseawind|multipart/form-data)",
        r"(?i)\b(?:kns|cf)\.duba\.net\b.*(?:kns-query|query3)",
        r"(?i)\bhttp/1\.0\b.*\bmultipart/form-data\b.*\bcontent-length\s*:\s*[1-9]\d*",
    ],
    "Spider_Anti": [
        r"(?i)\b(spider|crawler|bot)\b",
        r"(?i)\bpython-requests/[0-9.]+",
        r"(?i)\bgo-http-client/[0-9.]+",
        r"(?i)\bcurl/[0-9.]+",
    ],
    "SQL_Injection": [
        r"(?i)\binjectjql\b",
        r"(?i)\bjql\s*=",
        r"(?i)\bjql\b",
        r"(?i)\bcql\b",
        r"(?i)\bissueNav/1/issueTable\b",
        r"(?i)\bQueryComponent!Jql\.jspa\b",
        r"(?i)\bQueryComponent(?:Renderer(?:Edit|Value))?!Default\.jspa\b",
        r"(?i)\bunion\s+select\b",
        r"(?i)\b(or|and)\s+1=1\b",
        r"(?i)\b(?:project|assignee|resolution)\s*(?:=|%3d)\s*",
        r"(?i)\border\s+by\b|%20order%20by%20",
        r"(?i)\bcurrentUser\s*\(",
        r"(?i)/(?:glm|deepseek)/v1/chat/completions\b.*\bauthorization\s*:\s*bearer\s+dcm_",
        r"(?i)/awstatstotals(?:/awstatstotals)?\.php\b.*\bsort\b",
        r"(?i)/(?:cgi-bin|pages|stat|apache2-default)/awstatstotals\.php\b",
        r"(?i)/confluence/plugins/servlet/confluence/placeholder/macro-heading\b.*\bdefinition=",
        r"(?i)/(?:jira/rest/api/2/search|jira/jira-api/rest/api/2/search|confluence/rest/api/search)\b",
        r"(?i)/jira/rest/synapse/latest/synapseTree/expandNode\b",
    ],
    "Anti_leech": [
        r"(?i)\bdis_k=[0-9a-f]{16,}\b",
        r"(?i)\bdis_t=\d{9,}\b",
        r"(?i)\bfromtag=\d{5,}\b",
        r"(?i)\btpp/1\.2\b",
        r"(?i)\.(?:mp4|mp3|flv)(?:\b|\?)",
        r"(?i)(?:stream\.tencentmusic\.com|music\.tc\.qq\.com)",
        r"(?i)(?:mv[0-9]+\.music\.tc\.qq\.com|qqmusic_(?:fromtag|uin|key))",
        r"(?i)/[0-9a-f]{48,}[^?\s]*/qmmv_[^?\s]+\.mp4(?:\?|$)",
        r"(?i)\bfname=qmmv_[^&\s]+\.mp4\b",
        r"(?i)\bwxrefresh_token\b",
        r"(?i)\bjdmall;android;version/",
    ],
    "Path_Traversal": [
        r"\.\./",
        r"\\\.\.\\",
        r"(?i)(?:%5c|\\)\.\.(?:%5c|\\)",
        r"(?i)\.\.%2f|%2e%2e|%252e%252e",
        r"(?i)/etc/passwd|/windows/win.ini",
        r"(?i)\\windows\\win\.ini|\\winnt/\\win\.ini",
        r"(?i)/phpmyadmin(?:/|\b|$)",
        r"(?i)trinity\.txt(?:%2e|\.)bak",
        r"(?i)(?:%00|\x00)",
        r"(?i)/WEB-INF\.?/web\.xml\b",
        r"(?i)/(?:CHANGELOG\.txt|active\.log|a_d/install/data\.sql|server-status)\b",
        r"(?i)/(?:shoutbox|news|webcalendar)/[^?\s]+\.php\b",
    ],
    "Sensitive_Info_Filter": [
        r"(?i)/openkylin/dists/[^?\s]+/inrelease\b",
        r"(?i)/ubuntu/pool/[^?\s]+\.deb\b",
        r"(?i)/ubuntu/dists/[^?\s]+/inrelease\b",
        r"(?i)/centos-vault/[^?\s]+/repodata/repomd\.xml\b",
        r"(?i)/yum/[^?\s]+/repodata/repomd\.xml\b",
        r"(?i)/community/webajax/settings/getperson\b",
        r"(?i)/community/webajax/settings/getuserinfo\b",
        r"(?i)/community/webajax/ucenter_ajax/(?:getpersonmsg|getdirectleader|getsubordinate)\b",
        r"(?i)/community/webajax/calendar_ajax/getroombydate\b",
        r"(?i)/(?:deepseek|glm)/v1/chat/completions\b",
        r"(?i)/api/ds/query\b",
        r"(?i)/platform/uploadtoken\b",
        r"(?i)/postdata/[^?\s]*(?:token|user)[^?\s]*",
        r"(?i)\b(?:openai/python|debian apt-http|libdnf)\b",
        r"(?i)\bqt\.gtimg\.cn\b.*(?:s_usDJI|s_sh000001|s_sz399001)",
        r"(?i)^/q=s_(?:us|hk|sh|sz)[A-Za-z0-9_,]+",
        r"(?i)/deepinid-sync/\d+/",
        r"(?i)/(?:d|download)\b.*\b(?:dn|ttl|clientip|type)\b",
        r"(?i)/v2/yueku/special_album_recommend\b",
        r"(?i)/thsft(?:_dist)?/",
    ],
    "Download_limit": [
        r"(?i)/_/download/",
        r"(?i)\bcontextbatch\b",
        r"(?i)\bbatch\b",
        r"(?i)documentconversion",
        # 高漏报补充：更新器/分发文件下载链路
        r"(?i)/per-plugin/dl/",
        r"(?i)/update/(?:autodownloads|[^?\s]+)",
        r"(?i)/filestreamingservice/files/[0-9a-f-]{12,}",
        r"(?i)\.(?:ini|conf|dat|crx3|exe)(?:\b|\?)",
        r"(?i)\b(?:huorong/updater|microsoft bits/[0-9.]+|officeclicktorun|sogou_updater)\b",
        r"(?i)/config/cloudconfig\.ini\b",
        r"(?i)/upgrade8/\d+/upgrade-x64\.conf\b",
        r"(?i)/(?:defend|conf|duba|mailmaster|cbs_down)/[^?\s]+\.(?:ini|conf|exe)\b",
        r"(?i)\bfile\.drivergenius\.com\b.*cloudconfig\.ini",
        r"(?i)\bdown-tencent\.huorong\.cn\b.*upgrade-x64\.conf",
    ],
    "OS_CMD_Injection": [
        r"(?i)(;|\|\||&&)\s*(cat|ls|whoami|id|curl|wget|bash|sh)\b",
        r"(?i)\b(cmd|powershell|pwsh|bash|sh)\b",
        r"(?i)(?:\$\(|%24%28|`)",
        r"(?i)(?:%0d%0a|%0a%0d|%0a|%0d)",
        r"(?i)/(?:blazeds|samples)/messagebroker/amf\b",
        r"(?i)\bcontent-type\s*:\s*application/x-amf\b",
        r"(?i)/(?:cgi-bin/)?twiki/bin/view\b|/(?:bin/view)\b",
        r"(?i)/plus/car\.php\b",
    ],
    "Web_Plugin_Bug": [
        r"(?i)/(?:plugins|plugin|wp-content|wp-includes)/",
        r"(?i)\b(?:struts|weblogic|shiro|spring|jira|confluence)\b",
        r"(?i)\b(?:cve-\d{4}-\d+)\b",
        # 高漏报补充：已观测到的插件/中间件探测路径与 JNDI 载荷
        r"(?i)^/level/\d+/exec/show/config/cr(?:\b|/|$)",
        r"(?i)/(?:phpinfo\.php|https-admserv/bin/index|crowd/admin/uploadplugin\.action)\b",
        r"(?i)\$\{jndi:(?:ldap|rmi|dns)://",
        r"(?i)/(?:wls-wsat|currentsetting\.htm|vulnerable_request_get)\b",
        r"(?i)\b(?:apache tomcat|jetty|jboss|log4j)\b",
        r"(?i)class\.module\.classloader\.urls\[\d+\]",
        r"(?i)/(?:admin|login|debug/pprof)(?:/|\b)",
        r"(?i)/jira/rest/api/latest/groupuserpicker\b",
    ],
    "XML_Attack": [
        r"(?i)\bcontent-type\s*:\s*application/xml\b",
        r"(?i)/config/cloudconfig\.ini\b.*\bapplication/xml\b",
        r"(?i)\bfile\.drivergenius\.com\b.*\bapplication/xml\b",
        r"(?i)<!(?:entity|doctype)\b|<\?xml\b",
        r"(?i)\bxxe\b|SYSTEM\s+[\"'](?:file|http|https)://",
    ],
    "Web_Server_Bug": [
        r"(?i)\brange\s*:\s*bytes=-\d+,-9223372036854775807\b",
        r"(?i)/servlet/org\.apache\.catalina\.servlets\.DefaultServlet/",
        r"(?i)/uploadfiles/[^?\s]+\.png/\.php\b",
        r"(?i)\bLD_PRELOAD\b|/proc/self/fd/0\b",
        r"(?i)/cgi-bin/index\.cgi\b",
        r"(?i)\\winnt/\\win\.ini",
    ],
}

LEGIT_PARAM_PATTERNS = [
    r"action=\d+",
    r"id=\d+",
    r"atl_token=[A-Za-z0-9_]+",
    r"decorator=dialog",
    r"inline=true",
    r"anonymous=true",
    r"spaceKey=\w+",
]

# 全局扁平化规则池
REGEX_GROUPS: Dict[str, List[str]] = {
    "sql": SQL_PATTERNS.copy(),
    "xss": XSS_PATTERNS.copy(),
    "traversal": TRAVERSAL_PATTERNS.copy(),
    "cmd": CMD_PATTERNS.copy(),
    "http_proto": HTTP_PROTO_PATTERNS.copy(),
}
for _evt, _plist in EVENT_TYPE_RULE_PATTERNS.items():
    _evt_slug = re.sub(r"[^a-z0-9]+", "_", _evt.lower()).strip("_")
    REGEX_GROUPS[f"evt_{_evt_slug}"] = _plist.copy()


def _build_flat_patterns(groups: Dict[str, List[str]]) -> List[Tuple[str, str, int, str]]:
    """
    返回 [(feature_name, group_name, group_index, pattern), ...]
    feature_name 固定，保证输入维度稳定。
    """
    items: List[Tuple[str, str, int, str]] = []
    for gname in sorted(groups.keys()):
        for i, pat in enumerate(groups[gname]):
            gslug = re.sub(r"[^a-z0-9]+", "_", gname.lower()).strip("_")
            fname = f"regex_bin_{gslug}_p{i:02d}"
            items.append((fname, gname, i, pat))
    return items


ALL_FLAT_PATTERNS: List[Tuple[str, str, int, str]] = _build_flat_patterns(REGEX_GROUPS)


def _s(x: Any) -> str:
    return "" if x is None else str(x)


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def _safe_unquote(s: str) -> str:
    if not s:
        return ""
    s2 = s.replace("+", " ")
    try:
        return unquote(s2, errors="replace")
    except TypeError:
        return unquote(s2)


def _normalize_http_raw_for_analysis(http_field: str) -> str:
    return _s(http_field).replace("#015#012", "\n").replace("\r\n", "\n").replace("\\/", "/")


def _extract_body_from_http_field(http_field: Any) -> str:
    s = _s(http_field)
    if not s:
        return ""
    h = s.replace("#015#012", "\n").replace("#012", "\n").replace("\\/", "/")
    if "\n\n" in h:
        return h.split("\n\n", 1)[1].strip()
    m = re.search(r"\r?\n\r?\n(.+)", h, re.DOTALL)
    return m.group(1).strip() if m else ""


def entropy(text: str) -> float:
    if not text:
        return 0.0
    c = Counter(text)
    n = len(text)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def _binary_pattern_features(text: str) -> Dict[str, float]:
    """
    每条正则退化为一个布尔维度（0/1），形成固定高维空间。
    """
    out: Dict[str, float] = {}
    if not text:
        for fname, _, _, _ in ALL_FLAT_PATTERNS:
            out[fname] = 0.0
        return out
    for fname, _, _, pat in ALL_FLAT_PATTERNS:
        out[fname] = float(int(bool(re.search(pat, text, re.IGNORECASE))))
    return out


def _group_multihot_features(binary_map: Dict[str, float]) -> Dict[str, float]:
    """
    分组 multi-hot 统计（不含人工权重）：
    - group_*_hit_count
    - group_*_any
    """
    out: Dict[str, float] = {}
    for gname in sorted(REGEX_GROUPS.keys()):
        keys = [f"regex_bin_{_slug(gname)}_p{i:02d}" for i in range(len(REGEX_GROUPS[gname]))]
        c = float(sum(binary_map.get(k, 0.0) for k in keys))
        out[f"group_{_slug(gname)}_hit_count"] = c
        out[f"group_{_slug(gname)}_any"] = float(int(c > 0))
    return out


def parse_query(uri: str) -> str:
    return uri.split("?", 1)[1] if "?" in uri else ""


def _normalize_row(row: pd.Series) -> Dict[str, Any]:
    parsed = row.get("http_parsed", {}) or {}
    if isinstance(parsed, dict) and parsed:
        query_obj = parsed.get("query", {}) or {}
        if isinstance(query_obj, dict):
            query_pairs = []
            for k, vals in query_obj.items():
                if isinstance(vals, list):
                    for v in vals:
                        query_pairs.append((str(k), _s(v)))
                else:
                    query_pairs.append((str(k), _s(vals)))
            query = "&".join(f"{k}={v}" for k, v in query_pairs)
        else:
            query = _s(query_obj)
        body = parsed.get("body", "")
        body = body if isinstance(body, str) else _s(body)
        if not (body or "").strip():
            body = _extract_body_from_http_field(row.get("http", ""))
        return {
            "http": _s(row.get("http", "")),
            "uri": _s(parsed.get("url", row.get("uri", ""))),
            "path": _s(parsed.get("path", row.get("path", ""))),
            "query": query,
            "headers": parsed.get("headers", {}) or {},
            "body": body,
        }
    return {
        "http": _s(row.get("http", "")),
        "uri": _s(row.get("uri", "")),
        "path": _s(row.get("path", "")),
        "query": _s(row.get("query", "")),
        "headers": row.get("headers", {}) or {},
        "body": _s(row.get("body", "")),
    }


def extract_basic_features(
    uri: str,
    path: str,
    query: str,
    body: str,
    method: str,
    headers: Dict[str, Any],
) -> Dict[str, float]:
    uri_len_raw = len(uri)
    query_len_raw = len(query)
    body_len_raw = len(body)
    param_count = len(parse_qsl(query, keep_blank_values=True)) if query else 0
    path_depth = len([x for x in (path or "").split("/") if x])
    path_numeric_density = len(re.findall(r"\d+", path)) / max(len(path), 1)
    special_ratio = len(re.findall(r"[^a-zA-Z0-9/_\-\.]", uri)) / max(uri_len_raw, 1)
    digit_ratio = len(re.findall(r"\d+", uri)) / max(uri_len_raw, 1)
    has_cookie = int(bool(headers.get("Cookie", "") or headers.get("cookie", "")))
    has_ua = int(bool(headers.get("User-Agent", "") or headers.get("user-agent", "")))

    return {
        "is_get": float(int(method == "GET")),
        "path_depth": float(path_depth),
        "path_numeric_density": float(path_numeric_density),
        "uri_len": float(math.log1p(min(uri_len_raw, 512))),
        "query_len_clip": float(math.log1p(min(query_len_raw, 256))),
        "body_len_clip": float(math.log1p(min(body_len_raw, 1024))),
        "param_count": float(param_count),
        "path_entropy": float(entropy(path)),
        "query_entropy": float(entropy(query)),
        "raw_entropy": float(entropy((uri + " " + path + " " + query + " " + body).lower())),
        "special_ratio": float(special_ratio),
        "digit_ratio": float(digit_ratio),
        # 仅统计有效 %xx 编码片段，避免把普通百分号噪声算进去
        "url_encoding_ratio": float(len(re.findall(r"%[0-9a-fA-F]{2}", uri)) / max(float(len(uri)), 1.0)),
        "double_encoding_hint": float(int("%25" in uri.lower())),
        "is_short_query": float(int(query_len_raw < 40)),
        "has_cookie": float(has_cookie),
        "has_ua": float(has_ua),
        "behavior_score": float(
            0.03 * has_cookie
            + 0.02 * has_ua
            + 0.01 * int(bool(headers.get("Referer", "") or headers.get("referer", "")))
        ),
    }


def extract_regex_rule_features(
    raw: str,
    raw_for_cmd: str,
    raw_with_headers: str,
    http_norm: str,
) -> Dict[str, float]:
    # 统一扫描文本：全局 0/1 pattern space
    analysis_text = "\n".join([raw, raw_for_cmd, raw_with_headers, http_norm]).strip()
    binary = _binary_pattern_features(analysis_text)
    group = _group_multihot_features(binary)

    out: Dict[str, float] = {}
    out.update(binary)
    out.update(group)
    out["regex_total_hits"] = float(sum(binary.values()))
    return out


def extract_features(row: pd.Series) -> Dict[str, Any]:
    req = _normalize_row(row)
    uri = req["uri"]
    path = req["path"]
    headers = req["headers"]
    body = req["body"]
    method = _s(row.get("method", "")).upper()
    parsed = urlparse(uri)
    query = req["query"] or parsed.query or parse_query(uri)

    ua = _s(headers.get("User-Agent", "") or headers.get("user-agent", ""))
    referer = _s(headers.get("Referer", "") or headers.get("referer", ""))
    raw = (uri + " " + path + " " + query + " " + body).lower()
    raw_for_cmd = (raw + " " + _safe_unquote(query + "&" + body).lower()).strip()
    raw_with_headers = (raw + " " + ua + " " + referer).strip()
    http_norm = _normalize_http_raw_for_analysis(req.get("http", ""))

    basic = extract_basic_features(uri, path, query, body, method, headers)
    regex = extract_regex_rule_features(raw, raw_for_cmd, raw_with_headers, http_norm)

    bin_dims = [v for k, v in regex.items() if k.startswith("regex_bin_")]
    raw_len = len(raw)
    special_ratio_raw = (len(re.findall(r"\W", raw)) / max(raw_len, 1)) if raw_len > 0 else 0.0

    extras = {
        # 统计学元特征（不含人工权重）
        "regex_active_dims": float(sum(bin_dims)),
        "raw_text_len": float(raw_len),
        "raw_special_char_ratio": float(special_ratio_raw),
        "hex_pattern_hits": float(len(re.findall(r"(?i)(?:0x[0-9a-f]{2,}|\\x[0-9a-f]{2})", raw))),
        "is_whitelisted_path": float(int(is_whitelisted_path(path or uri))),
        "has_legit_params": float(int(sum(1 for p in LEGIT_PARAM_PATTERNS if re.search(p, query)) >= 2)),
        "is_success_response": float(int(str(row.get("ser_status_code", "")).startswith("2"))),
    }
    return {**basic, **regex, **extras}


def _resolve_feature_n_jobs() -> int:
    raw = os.environ.get("WAF_FEATURE_N_JOBS", "").strip()
    if raw.isdigit():
        return max(1, int(raw))
    cpu = os.cpu_count() or 4
    if cpu <= 1:
        return 1
    return max(1, min(16, cpu - 1))


def _extract_features_for_chunk(chunk: pd.DataFrame) -> List[Dict[str, Any]]:
    if len(chunk) == 0:
        return []
    return [extract_features(chunk.iloc[i]) for i in range(len(chunk))]


def _feature_chunk_boundaries(n_rows: int, n_chunks: int) -> List[Tuple[int, int]]:
    if n_rows <= 0 or n_chunks <= 0:
        return []
    n_chunks = min(n_chunks, n_rows)
    edges = np.linspace(0, n_rows, n_chunks + 1, dtype=np.int64)
    return [(int(edges[i]), int(edges[i + 1])) for i in range(n_chunks) if edges[i] < edges[i + 1]]


def _feature_extraction_show_progress(num_rows: int) -> bool:
    if num_rows <= 0:
        return False
    v = os.environ.get("WAF_FEATURE_PROGRESS", "").strip().lower()
    if v in ("0", "false", "no", "off"):
        return False
    if v in ("1", "true", "yes", "on"):
        return True
    return num_rows >= 500 and sys.stderr.isatty()


def build_feature_df(df: pd.DataFrame) -> pd.DataFrame:
    n = len(df)
    n_jobs = _resolve_feature_n_jobs()
    use_parallel = n_jobs > 1 and n >= 2000

    if not use_parallel:
        iterator = df.iterrows()
        if _feature_extraction_show_progress(n):
            try:
                from tqdm.auto import tqdm

                iterator = tqdm(iterator, total=n, desc="feature_extract", unit="rows", dynamic_ncols=True)
            except ImportError:
                pass
        rows: List[Dict[str, Any]] = []
        for _, r in iterator:
            rows.append(extract_features(r))
        return pd.DataFrame(rows)

    chunk_bounds = _feature_chunk_boundaries(n, n_jobs)
    tasks = chunk_bounds
    if _feature_extraction_show_progress(n):
        try:
            from tqdm.auto import tqdm

            tasks = tqdm(chunk_bounds, total=len(chunk_bounds), desc="feature_extract_parallel", unit="chunks")
        except ImportError:
            pass
    batches: List[List[Dict[str, Any]]] = Parallel(n_jobs=n_jobs, prefer="processes")(
        delayed(_extract_features_for_chunk)(df.iloc[s:e].copy()) for s, e in tasks
    )
    rows = [row for batch in batches for row in batch]
    return pd.DataFrame(rows)


class FeatureExtractor(BaseEstimator, TransformerMixin):
    def fit(self, X: pd.DataFrame, y: Any = None):
        return self

    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        return build_feature_df(X)


def _split_binary_and_continuous_features(feature_names: List[str]) -> Tuple[List[str], List[str]]:
    """
    将特征拆分为：
    - binary: 0/1 特征（建议直接 passthrough）
    - continuous: 连续值特征（建议 MinMaxScaler）
    """
    binary_exact = {
        "is_get",
        "double_encoding_hint",
        "is_short_query",
        "has_cookie",
        "has_ua",
        "is_whitelisted_path",
        "has_legit_params",
        "is_success_response",
    }
    binary_prefixes = ("regex_bin_",)
    binary_suffixes = ("_any",)

    binary_cols: List[str] = []
    continuous_cols: List[str] = []
    for col in feature_names:
        is_binary = (
            col in binary_exact
            or any(col.startswith(p) for p in binary_prefixes)
            or any(col.endswith(s) for s in binary_suffixes)
        )
        if is_binary:
            binary_cols.append(col)
        else:
            continuous_cols.append(col)
    return binary_cols, continuous_cols


def build_feature_pipeline(df: pd.DataFrame, label_column: str | None = None) -> Tuple[Pipeline, List[str]]:
    if label_column and label_column in df.columns:
        src_df = df.drop(columns=[label_column])
    else:
        src_df = df.copy()
    if len(src_df) == 0:
        raise ValueError("Training data is empty.")

    probe = pd.DataFrame([extract_features(src_df.iloc[0])])
    numeric_cols = probe.select_dtypes(include=["number"]).columns.tolist()
    if not numeric_cols:
        raise ValueError("No numeric feature columns found.")

    binary_cols, continuous_cols = _split_binary_and_continuous_features(numeric_cols)
    transformers = []
    if continuous_cols:
        transformers.append(("cont", MinMaxScaler(), continuous_cols))
    if binary_cols:
        transformers.append(("bin", "passthrough", binary_cols))

    preprocessor = ColumnTransformer(transformers=transformers, remainder="drop")
    pipeline = Pipeline(steps=[("feature", FeatureExtractor()), ("preprocessor", preprocessor)])
    return pipeline, numeric_cols


def transform_features(pipeline: Pipeline, df: pd.DataFrame, label_column: str | None = None) -> np.ndarray:
    if label_column and label_column in df.columns:
        src_df = df.drop(columns=[label_column])
    else:
        src_df = df.copy()
    return pipeline.transform(src_df)
