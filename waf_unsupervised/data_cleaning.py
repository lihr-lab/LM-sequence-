from __future__ import annotations

import re
from typing import Any

import pandas as pd

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b-\x0c\x0e-\x1f]")


def is_binary_noise(
    payload: Any,
    *,
    min_len: int = 10,
    invalid_char_ratio: float = 0.05,
    control_char_ratio: float = 0.05,
    head_window: int = 10,
) -> bool:
    """
    判断 HTTP 载荷是否为二进制乱码/非文本脏数据。
    返回 True 表示应丢弃（drop）。
    """
    if not isinstance(payload, str):
        return False

    text = payload.strip()
    if not text:
        return False

    n = len(text)
    if n < max(1, int(min_len)):
        return False

    # 1) Unicode replacement char 比例（常见于解码失败）
    replacement_count = text.count("\uFFFD")
    if (replacement_count / n) > float(invalid_char_ratio):
        return True

    # 2) 不可打印控制字符比例（过滤 CR/LF/TAB 之外的控制字符）
    control_count = len(_CONTROL_CHAR_RE.findall(text))
    if (control_count / n) > float(control_char_ratio):
        return True

    # 3) 前 N 个字符没有字母，通常不是可解析 HTTP 文本
    head = text[: max(1, int(head_window))]
    if re.search(r"[a-zA-Z]", head) is None:
        return True

    return False


def clean_binary_noise_rows(
    df: pd.DataFrame,
    *,
    http_col: str = "http",
    min_len: int = 10,
    invalid_char_ratio: float = 0.05,
    control_char_ratio: float = 0.05,
    head_window: int = 10,
) -> tuple[pd.DataFrame, int]:
    """
    清洗 DataFrame 中指定列的二进制乱码样本，返回 (clean_df, dropped_count)。
    """
    if http_col not in df.columns:
        return df, 0

    is_noise = df[http_col].apply(
        lambda x: is_binary_noise(
            x,
            min_len=min_len,
            invalid_char_ratio=invalid_char_ratio,
            control_char_ratio=control_char_ratio,
            head_window=head_window,
        )
    )
    dropped = int(is_noise.sum())
    if dropped <= 0:
        return df, 0
    cleaned = df.loc[~is_noise].copy().reset_index(drop=True)
    return cleaned, dropped


def _is_empty_http_parsed(value: Any) -> bool:
    """
    判定 http_parsed 是否“解析为空”。
    认为以下情况为空：
    - 缺失/None
    - 不是 dict
    - 空 dict
    - dict 内所有值都为空白字符串/None
    """
    if value is None:
        return True
    if not isinstance(value, dict):
        return True
    if len(value) == 0:
        return True

    for v in value.values():
        if v is None:
            continue
        if isinstance(v, str):
            if v.strip():
                return False
            continue
        # 非字符串且非 None，视为有效解析值
        return False
    return True


def clean_noncompliant_protocol_rows(
    df: pd.DataFrame,
    *,
    method_col: str = "method",
    parsed_col: str = "http_parsed",
    unknown_method_value: str = "UNKNOWN",
) -> tuple[pd.DataFrame, dict[str, int]]:
    """
    清洗协议不合规样本，返回 (clean_df, stats)。

    过滤条件：
    1) method == UNKNOWN（大小写不敏感）
    2) http_parsed 为空（缺失/空对象/字段全空）
    """
    if len(df) == 0:
        return df, {"dropped_method_unknown": 0, "dropped_http_parsed_empty": 0, "dropped_total": 0}

    if method_col in df.columns:
        unknown_mask = (
            df[method_col]
            .astype(str)
            .str.strip()
            .str.upper()
            .eq(str(unknown_method_value).strip().upper())
        )
    else:
        unknown_mask = pd.Series(False, index=df.index)

    if parsed_col in df.columns:
        parsed_empty_mask = df[parsed_col].apply(_is_empty_http_parsed)
    else:
        # 没有 http_parsed 字段时，按“解析为空”处理
        parsed_empty_mask = pd.Series(True, index=df.index)

    drop_mask = unknown_mask | parsed_empty_mask
    dropped_total = int(drop_mask.sum())
    stats = {
        "dropped_method_unknown": int(unknown_mask.sum()),
        "dropped_http_parsed_empty": int(parsed_empty_mask.sum()),
        "dropped_total": dropped_total,
    }
    if dropped_total <= 0:
        return df, stats

    cleaned = df.loc[~drop_mask].copy().reset_index(drop=True)
    return cleaned, stats


def _path_from_row(row: pd.Series, path_col: str = "path", parsed_col: str = "http_parsed") -> str:
    parsed = row.get(parsed_col, None)
    if isinstance(parsed, dict):
        path = parsed.get("path", None)
        if path is not None:
            return str(path)
        url = parsed.get("url", None)
        if isinstance(url, str) and url:
            return url.split("?", 1)[0]
    path = row.get(path_col, "")
    return "" if path is None else str(path)


def is_empty_path_row(row: pd.Series, *, path_col: str = "path", parsed_col: str = "http_parsed") -> bool:
    """
    判断一条样本是否缺少可用 URL path。
    """
    path = _path_from_row(row, path_col=path_col, parsed_col=parsed_col)
    return not path.strip()


def clean_empty_path_rows(
    df: pd.DataFrame,
    *,
    path_col: str = "path",
    parsed_col: str = "http_parsed",
) -> tuple[pd.DataFrame, int]:
    """
    清洗 path 为空的样本，返回 (clean_df, dropped_count)。
    """
    if len(df) == 0:
        return df, 0

    is_empty = df.apply(
        lambda row: is_empty_path_row(row, path_col=path_col, parsed_col=parsed_col),
        axis=1,
    )
    dropped = int(is_empty.sum())
    if dropped <= 0:
        return df, 0
    cleaned = df.loc[~is_empty].copy().reset_index(drop=True)
    return cleaned, dropped
