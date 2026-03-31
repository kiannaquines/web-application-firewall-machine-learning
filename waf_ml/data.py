import csv
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

from sklearn.model_selection import StratifiedGroupKFold

from .preprocessing import normalize_payload
from .runtime import canonicalize_request


LABELS = ("valid", "xss", "sqli", "cmdi", "path-traversal")
PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Record:
    pattern: str
    label: str
    source: str
    weight: float = 1.0
    family: str = ""


@dataclass(frozen=True)
class DatasetBundle:
    development: List[Record]
    final_test: List[Record]
    challenge: List[Record]
    runtime_challenge: List[Record]
    summary: Dict[str, object]


def _load_json_records(path: Path) -> List[Dict[str, str]]:
    raw = json.loads(path.read_text())
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict) and {"pattern", "type"} <= set(raw):
        patterns = raw["pattern"]
        labels = raw["type"]
        return [{"pattern": pattern, "type": label} for pattern, label in zip(patterns, labels)]
    raise ValueError(f"Unsupported JSON format in {path}")


def _load_csv_records(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        return [{"pattern": row["pattern"], "type": row["type"]} for row in reader]


def load_source_records(path: Path) -> List[Dict[str, str]]:
    if path.suffix.lower() == ".json":
        return _load_json_records(path)
    if path.suffix.lower() == ".csv":
        return _load_csv_records(path)
    raise ValueError(f"Unsupported source file: {path}")


def default_sources() -> Sequence[Path]:
    return (
        PROJECT_ROOT / "datasets" / "final_completed_cleaned.json",
        PROJECT_ROOT / "datasets" / "valid_url_routes.json",
        PROJECT_ROOT / "datasets" / "clean_cmdi.json",
        PROJECT_ROOT / "datasets" / "clean_sqli.json",
        PROJECT_ROOT / "attack_payloads.csv",
    )


def valid_sample_weight(pattern: str) -> float:
    stripped = pattern.strip().lower()
    if not stripped:
        return 0.25
    if stripped in {"*", "*/*"}:
        return 0.35
    if re.fullmatch(r"[a-z-]+/\d+(?:\.\d+)+", stripped):
        return 0.45
    if re.fullmatch(r"[\w*-]+(?:;q=0\.\d+)?(?:,\s*[\w*-]+(?:;q=0\.\d+)?)*", stripped):
        return 0.55
    return 1.0


def attack_family_key(label: str, pattern: str) -> str:
    normalized = normalize_payload(pattern).normalized
    normalized = re.sub(r"\d+", "0", normalized)
    normalized = re.sub(r"[a-z]{4,}", "token", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return f"{label}:{normalized[:120]}"


def record_family(label: str, pattern: str) -> str:
    if label == "valid":
        return f"valid:{normalize_payload(pattern).normalized[:120]}"
    return attack_family_key(label, pattern)


def expand_realistic_valid_samples(records: Sequence[Record], per_route_limit: int = 1200) -> List[Record]:
    valid_routes = []
    seen = set()
    for record in records:
        if record.label != "valid":
            continue
        route = record.pattern.strip()
        if route.startswith("/") and route not in seen:
            seen.add(route)
            valid_routes.append(route)
        if len(valid_routes) >= per_route_limit:
            break

    templates = [
        "GET {route}",
        "path={route}&page=1",
        "redirect={route}&tab=overview",
        '{{"path":"{route}","page":1,"sort":"recent"}}',
        "referer=https://example.com{route}&lang=en-US",
        "resource={route}&include=summary,author",
    ]
    expanded: List[Record] = []
    for route in valid_routes:
        for template in templates:
            pattern = template.format(route=route)
            expanded.append(
                Record(
                    pattern=pattern,
                    label="valid",
                    source="generated_valid_templates",
                    weight=1.0,
                    family=record_family("valid", pattern),
                )
            )
    return expanded


def craft_challenge_samples(records: Sequence[Record], per_label_limit: int = 50) -> List[Record]:
    grouped: Dict[str, List[Record]] = defaultdict(list)
    for record in records:
        if record.label != "valid" and len(grouped[record.label]) < per_label_limit:
            grouped[record.label].append(record)

    challenge: List[Record] = []
    for label, label_records in grouped.items():
        for record in label_records:
            normalized = normalize_payload(record.pattern)
            base = normalized.normalized or normalized.raw
            url_wrapped = f"next=%2Fdashboard&input={base.replace('/', '%2F')}"
            base64_wrapped = f"payload={base.encode('utf-8').hex()}"
            mixed = f"username=alice&note=safe&search={base}"
            for pattern in (url_wrapped, base64_wrapped, mixed):
                challenge.append(
                    Record(
                        pattern=pattern,
                        label=label,
                        source="challenge",
                        weight=1.0,
                        family=record_family(label, pattern),
                    )
                )
    return challenge


def _runtime_method(label: str, pattern: str) -> str:
    normalized = normalize_payload(pattern).normalized
    if label == "valid" and pattern.strip().startswith("/"):
        return "GET"
    if label in {"sqli", "path-traversal"}:
        return "GET"
    if label in {"xss", "cmdi"}:
        return "POST"
    if normalized.startswith("{") and normalized.endswith("}"):
        return "POST"
    if "=" in normalized:
        return "POST"
    return "GET"


def _parse_form_payload(payload: str) -> Dict[str, str]:
    form: Dict[str, str] = {}
    for field in payload.split("&"):
        if not field:
            continue
        if "=" in field:
            key, value = field.split("=", 1)
        else:
            key, value = "input", field
        key = key.strip() or "input"
        form[key] = value.strip()
    return form or {"input": payload}


def record_to_runtime_request(record: Record) -> Record:
    normalized = normalize_payload(record.pattern)
    payload = normalized.normalized or normalized.raw
    method = _runtime_method(record.label, record.pattern)
    headers: Dict[str, str] = {"user-agent": "waf-runtime-dataset/1.0"}
    query: Dict[str, str] = {}
    form: Dict[str, str] = {}
    json_body = None

    if record.label == "valid" and record.pattern.strip().startswith("/"):
        path = record.pattern.strip()
        query = {"page": "1", "lang": "en"}
    elif record.label == "path-traversal":
        path = "/download"
        query = {"file": payload}
    elif record.label == "sqli":
        path = "/search"
        query = {"q": payload, "page": "1"}
    elif record.label == "xss":
        path = "/submit"
        json_body = {"comment": payload, "preview": True}
        headers["content-type"] = "application/json"
    elif record.label == "cmdi":
        path = "/submit"
        form = {"host": payload, "mode": "ping"}
        headers["content-type"] = "application/x-www-form-urlencoded"
    elif payload.startswith("{") and payload.endswith("}"):
        path = "/submit"
        try:
            json_body = json.loads(payload)
        except json.JSONDecodeError:
            json_body = {"input": payload}
        headers["content-type"] = "application/json"
        method = "POST"
    elif "=" in payload:
        path = "/submit"
        form = _parse_form_payload(payload)
        headers["content-type"] = "application/x-www-form-urlencoded"
        method = "POST"
    else:
        path = "/search" if method == "GET" else "/submit"
        if method == "GET":
            query = {"q": payload}
        else:
            json_body = {"input": payload}
            headers["content-type"] = "application/json"

    runtime_pattern = canonicalize_request(
        method=method,
        path=path,
        query=query,
        form=form,
        json_body=json_body,
        headers=headers,
        remote_addr="127.0.0.1",
    )
    return Record(
        pattern=runtime_pattern,
        label=record.label,
        source=f"{record.source}:runtime",
        weight=record.weight,
        family=f"{record.family}:runtime",
    )


def convert_records_to_runtime_requests(records: Sequence[Record]) -> List[Record]:
    return [record_to_runtime_request(record) for record in records]


def load_advanced_runtime_challenge(path: Optional[Path] = None) -> List[Record]:
    challenge_path = path or PROJECT_ROOT / "samples" / "advanced_validation_requests.json"
    if not challenge_path.exists():
        return []

    samples = json.loads(challenge_path.read_text())
    records: List[Record] = []
    for index, sample in enumerate(samples):
        query = {str(key): str(value) for key, value in dict(sample.get("params", {}) or {}).items()}
        form = {
            str(key): str(value)
            for key, value in dict(sample.get("form", sample.get("data", {})) or {}).items()
        }
        headers = {
            str(key).lower(): str(value)
            for key, value in dict(sample.get("headers", {}) or {}).items()
        }
        records.append(
            Record(
                pattern=canonicalize_request(
                    method=str(sample.get("method", "GET")).upper(),
                    path=str(sample.get("path", "/")),
                    query=query,
                    form=form,
                    json_body=sample.get("json"),
                    headers=headers,
                    remote_addr="127.0.0.1",
                ),
                label=str(sample.get("label", sample.get("type", "valid"))),
                source=challenge_path.name,
                family=f"runtime-challenge:{index}",
            )
        )
    return records


def deduplicate_records(records: Iterable[Record]) -> List[Record]:
    by_pattern: Dict[str, set] = defaultdict(set)
    for record in records:
        by_pattern[record.pattern].add(record.label)

    cleaned: List[Record] = []
    seen = set()
    for record in records:
        if record.label not in LABELS:
            continue
        pattern = record.pattern.strip()
        if not pattern:
            pattern = ""
        if len(by_pattern[record.pattern]) > 1:
            continue
        key = (pattern, record.label)
        if key in seen:
            continue
        seen.add(key)
        cleaned.append(
            Record(
                pattern=pattern,
                label=record.label,
                source=record.source,
                weight=record.weight,
                family=record.family or record_family(record.label, pattern),
            )
        )
    return cleaned


def build_dataset_bundle(random_state: int = 42, representation: str = "http") -> DatasetBundle:
    if representation not in {"http", "payload"}:
        raise ValueError("representation must be 'http' or 'payload'")
    records: List[Record] = []
    for source_path in default_sources():
        for row in load_source_records(source_path):
            label = str(row["type"]).strip()
            pattern = str(row["pattern"])
            weight = valid_sample_weight(pattern) if label == "valid" else 1.0
            records.append(
                Record(
                    pattern=pattern,
                    label=label,
                    source=source_path.name,
                    weight=weight,
                    family=record_family(label, pattern),
                )
            )

    records = deduplicate_records(records)
    records.extend(expand_realistic_valid_samples(records))
    records = deduplicate_records(records)
    if representation == "http":
        records = convert_records_to_runtime_requests(records)

    labels = [record.label for record in records]
    groups = [record.family for record in records]
    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=random_state)
    dev_idx, test_idx = next(splitter.split(records, labels, groups))
    development = [records[index] for index in dev_idx]
    final_test = [records[index] for index in test_idx]
    challenge = craft_challenge_samples(final_test)
    if representation == "http":
        challenge = convert_records_to_runtime_requests(challenge)
    runtime_challenge = load_advanced_runtime_challenge()

    summary = {
        "representation": representation,
        "development_rows": len(development),
        "final_test_rows": len(final_test),
        "challenge_rows": len(challenge),
        "runtime_challenge_rows": len(runtime_challenge),
        "development_class_counts": dict(Counter(record.label for record in development)),
        "final_test_class_counts": dict(Counter(record.label for record in final_test)),
    }
    return DatasetBundle(
        development=development,
        final_test=final_test,
        challenge=challenge,
        runtime_challenge=runtime_challenge,
        summary=summary,
    )
