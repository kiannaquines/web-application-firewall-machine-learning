import json
import logging
import os
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional
from urllib.parse import parse_qsl, urlsplit

from .detector import WAFDetector


LOGGER = logging.getLogger(__name__)
SELECTED_HEADERS = (
    "content-type",
    "user-agent",
    "referer",
    "x-forwarded-for",
    "x-real-ip",
)
SENSITIVE_KEYS = {
    "authorization",
    "cookie",
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
}
SKIP_PATH_PREFIXES = ("/healthz", "/__waf__/authorize")


@dataclass(frozen=True)
class CanonicalRequest:
    method: str
    path: str
    query: Dict[str, Any]
    form: Dict[str, Any]
    json_body: Any
    headers: Dict[str, str]
    remote_addr: str = ""

    def model_input(self) -> str:
        return canonicalize_request(
            method=self.method,
            path=self.path,
            query=self.query,
            form=self.form,
            json_body=self.json_body,
            headers=self.headers,
            remote_addr=self.remote_addr,
        )


def build_detector_from_env() -> WAFDetector:
    detector = WAFDetector(
        artifact_path=os.getenv(
            "MODEL_ARTIFACT_PATH", "./artifacts/request_predictor_v2.joblib"
        )
    )
    if os.getenv("WAF_BLOCK_THRESHOLD"):
        detector.block_threshold = float(os.environ["WAF_BLOCK_THRESHOLD"])
    if os.getenv("WAF_ALLOW_THRESHOLD"):
        detector.allow_threshold = float(os.environ["WAF_ALLOW_THRESHOLD"])
    return detector


def _normalize_mapping(
    values: Optional[Mapping[str, Any]], *, redact: bool = False
) -> Dict[str, Any]:
    if not values:
        return {}

    normalized: Dict[str, Any] = {}
    for key in sorted(values):
        normalized_key = str(key).strip().lower()
        value = values[key]
        normalized[normalized_key] = _normalize_value(
            value, key=normalized_key, redact=redact
        )
    return normalized


def _normalize_value(value: Any, *, key: str = "", redact: bool = False) -> Any:
    if isinstance(value, Mapping):
        return {
            str(child_key).strip().lower(): _normalize_value(
                child_value,
                key=str(child_key).strip().lower(),
                redact=redact,
            )
            for child_key, child_value in sorted(value.items(), key=lambda item: str(item[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_normalize_value(item, key=key, redact=redact) for item in value]
    if value is None:
        return ""
    text = str(value).strip()
    if redact and key in SENSITIVE_KEYS:
        return "<redacted>"
    return text[:256]


def _stable_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def canonicalize_request(
    *,
    method: str,
    path: str,
    query: Optional[Mapping[str, Any]] = None,
    form: Optional[Mapping[str, Any]] = None,
    json_body: Any = None,
    headers: Optional[Mapping[str, Any]] = None,
    remote_addr: str = "",
    redact_sensitive: bool = False,
) -> str:
    canonical = {
        "method": str(method or "GET").upper(),
        "path": path or "/",
        "query": _normalize_mapping(query, redact=redact_sensitive),
        "form": _normalize_mapping(form, redact=redact_sensitive),
        "json": _normalize_value(json_body, redact=redact_sensitive),
        "headers": _normalize_mapping(headers, redact=redact_sensitive),
        "remote_addr": str(remote_addr or "").strip(),
    }
    return _stable_json(canonical)


def should_skip_path(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in SKIP_PATH_PREFIXES)


def build_edge_request_from_environ(environ: Mapping[str, str]) -> CanonicalRequest:
    request_uri = environ.get("HTTP_X_ORIGINAL_URI", environ.get("RAW_URI", "/"))
    parsed = urlsplit(request_uri)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    headers = {
        header: environ.get(environ_key, "")
        for header, environ_key in {
            "content-type": "HTTP_X_EDGE_CONTENT_TYPE",
            "user-agent": "HTTP_X_EDGE_USER_AGENT",
            "referer": "HTTP_X_EDGE_REFERER",
            "x-forwarded-for": "HTTP_X_EDGE_FORWARDED_FOR",
            "x-real-ip": "HTTP_X_EDGE_REAL_IP",
        }.items()
        if environ.get(environ_key)
    }
    return CanonicalRequest(
        method=environ.get("HTTP_X_ORIGINAL_METHOD", environ.get("REQUEST_METHOD", "GET")),
        path=parsed.path or "/",
        query=query,
        form={},
        json_body=None,
        headers=headers,
        remote_addr=environ.get("HTTP_X_EDGE_REAL_IP", ""),
    )


def build_request_from_flask(request: Any) -> CanonicalRequest:
    headers = {
        header: request.headers.get(header, "")
        for header in SELECTED_HEADERS
        if request.headers.get(header)
    }
    json_body = request.get_json(silent=True)
    form = request.form.to_dict(flat=True) if request.form else {}
    query = request.args.to_dict(flat=True) if request.args else {}
    return CanonicalRequest(
        method=request.method,
        path=request.path,
        query=query,
        form=form,
        json_body=json_body,
        headers=headers,
        remote_addr=request.headers.get("X-Forwarded-For", request.remote_addr or ""),
    )


def summarize_for_log(model_input: str, limit: int = 240) -> str:
    redacted = model_input.replace("\n", " ")
    return redacted[:limit]


def evaluate_request(
    detector: WAFDetector, canonical_request: CanonicalRequest
) -> Dict[str, Any]:
    return detector.predict(canonical_request.model_input())[0]


def build_log_record(
    *,
    request_id: str,
    stage: str,
    result: Mapping[str, Any],
    model_input: str,
) -> Dict[str, Any]:
    return {
        "request_id": request_id,
        "stage": stage,
        "predicted_class": result["predicted_class"],
        "confidence": round(float(result["confidence"]), 6),
        "action": result["action"],
        "payload_summary": summarize_for_log(model_input),
    }


def emit_decision_log(
    *,
    request_id: str,
    stage: str,
    result: Mapping[str, Any],
    model_input: str,
) -> None:
    LOGGER.info(
        _stable_json(
            build_log_record(
                request_id=request_id,
                stage=stage,
                result=result,
                model_input=model_input,
            )
        )
    )


def new_request_id() -> str:
    return uuid.uuid4().hex
