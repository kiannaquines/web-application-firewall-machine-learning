#!/usr/bin/env python3

import argparse
import csv
import json
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional

import requests


DEFAULT_TIMEOUT = 5.0


def load_samples(path: Path) -> List[Dict[str, Any]]:
    if path.suffix.lower() == ".json":
        raw = json.loads(path.read_text())
        if isinstance(raw, dict):
            return raw.get("samples", [])
        return raw
    if path.suffix.lower() == ".csv":
        with path.open(newline="", encoding="utf-8") as handle:
            return list(csv.DictReader(handle))
    raise ValueError(f"Unsupported file type: {path}")


def _coerce_mapping(value: Any) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): item for key, item in value.items()}


def _payload_preview(sample: Dict[str, Any]) -> str:
    for key in ("payload", "pattern", "name"):
        value = sample.get(key)
        if value:
            return str(value)
    for key in ("params", "json", "form", "data"):
        value = sample.get(key)
        if value:
            return json.dumps(value, sort_keys=True)
    return ""


def sample_to_request(sample: Dict[str, Any]) -> Dict[str, Any]:
    method = str(sample.get("method", "GET")).upper()
    path = str(sample.get("path", "/search"))
    payload = _payload_preview(sample)
    label = str(sample.get("label", sample.get("type", "unknown")))
    headers = _coerce_mapping(sample.get("headers"))
    params = _coerce_mapping(sample.get("params"))
    json_body = sample.get("json")
    form = _coerce_mapping(sample.get("form"))
    data = _coerce_mapping(sample.get("data"))
    name = str(sample.get("name", label))

    if params or json_body is not None or form or data:
        return {
            "name": name,
            "method": method,
            "path": path,
            "params": params or None,
            "json": json_body,
            "data": form or data or None,
            "headers": headers,
            "label": label,
            "payload": payload,
        }

    if method == "GET":
        return {
            "name": name,
            "method": method,
            "path": path,
            "params": {"q": payload},
            "json": None,
            "data": None,
            "headers": headers,
            "label": label,
            "payload": payload,
        }

    return {
        "name": name,
        "method": method,
        "path": path,
        "params": None,
        "json": {"input": payload},
        "data": None,
        "headers": headers,
        "label": label,
        "payload": payload,
    }


def send_sample(
    session: requests.Session, base_url: str, prepared: Dict[str, Any], timeout: float
) -> Dict[str, Any]:
    url = f"{base_url.rstrip('/')}{prepared['path']}"
    start = time.perf_counter()
    response = session.request(
        method=prepared["method"],
        url=url,
        params=prepared["params"],
        json=prepared["json"],
        data=prepared["data"],
        headers=prepared["headers"],
        timeout=timeout,
    )
    elapsed_ms = (time.perf_counter() - start) * 1000
    try:
        body = response.json()
    except ValueError:
        body = {"raw_body": response.text}
    waf = body.get("waf", {})
    blocked = response.status_code == 403 or body.get("error") == "request_blocked"
    return {
        "status_code": response.status_code,
        "latency_ms": round(elapsed_ms, 2),
        "blocked": blocked,
        "name": prepared["name"],
        "label": prepared["label"],
        "payload": prepared["payload"],
        "predicted_class": waf.get("predicted_class", body.get("predicted_class")),
        "confidence": waf.get("confidence", body.get("confidence")),
    }


def send_sample_with_new_session(
    base_url: str, prepared: Dict[str, Any], timeout: float
) -> Dict[str, Any]:
    with requests.Session() as session:
        return send_sample(session, base_url, prepared, timeout)


def print_live_result(result: Dict[str, Any], *, index: int, total: int) -> None:
    status = "BLOCKED" if result["blocked"] else "ALLOWED"
    print(
        "[{index}/{total}] {name} label={label} {status} status={status_code} latency_ms={latency} predicted={predicted} confidence={confidence} payload={payload}".format(
            index=index,
            total=total,
            name=result.get("name", "sample"),
            label=result["label"],
            status=status,
            status_code=result["status_code"],
            latency=result["latency_ms"],
            predicted=result.get("predicted_class") or "unknown",
            confidence=result.get("confidence"),
            payload=repr(result["payload"][:120]),
        ),
        flush=True,
    )


def summarize(results: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    rows = list(results)
    malicious = [row for row in rows if row["label"] != "valid"]
    benign = [row for row in rows if row["label"] == "valid"]
    true_positives = sum(1 for row in malicious if row["blocked"])
    false_negatives = sum(1 for row in malicious if not row["blocked"])
    false_positives = sum(1 for row in benign if row["blocked"])
    return {
        "total": len(rows),
        "true_positives": true_positives,
        "false_negatives": false_negatives,
        "false_positives": false_positives,
        "average_latency_ms": round(
            statistics.fmean(row["latency_ms"] for row in rows), 2
        )
        if rows
        else 0.0,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Replay authorized validation traffic against the protected app."
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--mode", choices=("single", "batch"), default="single")
    parser.add_argument("--input-file")
    parser.add_argument("--payload", help="Single payload to send.")
    parser.add_argument("--method", default="GET")
    parser.add_argument("--path", default="/search")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument(
        "--stream",
        action="store_true",
        help="Print each request result as soon as it completes.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    session = requests.Session()

    if args.mode == "single":
        sample = {
            "name": "single-request",
            "method": args.method,
            "path": args.path,
            "payload": args.payload or "health-check",
            "label": "unknown",
        }
        result = send_sample(
            session,
            args.base_url,
            sample_to_request(sample),
            timeout=args.timeout,
        )
        print_live_result(result, index=1, total=1)
        print(json.dumps(result, indent=2))
        return

    if not args.input_file:
        parser.error("--input-file is required for batch mode")

    samples = [sample_to_request(sample) for sample in load_samples(Path(args.input_file))]
    results: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as executor:
        futures = [
            executor.submit(
                send_sample_with_new_session,
                args.base_url,
                sample,
                args.timeout,
            )
            for sample in samples
        ]
        for index, future in enumerate(as_completed(futures), start=1):
            try:
                result = future.result()
            except requests.RequestException as exc:
                result = {
                    "status_code": 0,
                    "latency_ms": 0.0,
                    "blocked": False,
                    "name": "request-error",
                    "label": "error",
                    "payload": "",
                    "predicted_class": "request-error",
                    "confidence": None,
                    "error": str(exc),
                }
            results.append(result)
            if args.stream:
                print_live_result(result, index=index, total=len(samples))
    print(
        json.dumps(
            {
                "summary": summarize(results),
                "results": results,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
