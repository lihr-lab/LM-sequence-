from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse


WHITELIST_PATHS = [
    r"/jira/secure/WorkflowUIDispatcher\.jspa",
    r"/jira/secure/CommentAssignIssue!default\.jspa",
    r"/jira/secure/ShowIssuePicker\.jspa",
    r"/jira/rest/orderbycomponent/",
    r"/jira/rest/analytics/",
    r"/jira/rest/issueNav/",
    r"/jira/rest/wrm/",
    r"/confluence/rest/analytics-core/",
    r"/confluence/rest/viewtracker/",
    r"/confluence/rest/mywork/",
    r"/confluence/rest/quicknav/",
    r"/plugins/servlet/oidc/callback",
    # High-volume benign business traffic observed in FP analysis.
    r"^/mmtls(?:/|\?|$)",
]


def _safe_str(value: Any) -> str:
    return "" if value is None else str(value)


def extract_request_path(record: Any) -> str:
    if hasattr(record, "to_dict"):
        record = record.to_dict()
    if not isinstance(record, dict):
        return ""

    parsed = record.get("http_parsed")
    if isinstance(parsed, dict) and parsed.get("path"):
        return _safe_str(parsed.get("path"))

    for key in ("path", "uri"):
        value = _safe_str(record.get(key))
        if not value:
            continue
        if value.startswith(("http://", "https://")):
            return urlparse(value).path or value
        return value.split("?", 1)[0]
    return ""


def is_whitelisted_path(path_or_record: Any) -> bool:
    if isinstance(path_or_record, str):
        path = path_or_record
    else:
        path = extract_request_path(path_or_record)
    if not path:
        return False
    return any(re.search(pattern, path, re.IGNORECASE) for pattern in WHITELIST_PATHS)
