import re
from typing import Iterable, List

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

from .preprocessing import normalize_payload


TRAVERSAL_RE = re.compile(r"\.\./|%2e%2e|%252e%252e|/etc/passwd|system32")
HTML_JS_RE = re.compile(r"<script|onerror|onload|javascript:|<svg|<img|<iframe")
SQL_RE = re.compile(
    r"union select|select\b|sleep\(|benchmark\(|or 1=1|drop table|waitfor delay|pg_sleep|information_schema"
)
SHELL_RE = re.compile(r"[;|`$]|\b(?:cat|whoami|ls|curl|wget|bash|nc|python)\b")


class SuspiciousPatternFeatures(BaseEstimator, TransformerMixin):
    def fit(self, X: Iterable[object], y=None):
        return self

    def transform(self, X: Iterable[object]) -> np.ndarray:
        rows: List[List[float]] = []
        for payload in X:
            normalized = normalize_payload(payload)
            raw = normalized.raw
            text = normalized.normalized
            rows.append(
                [
                    float(len(raw)),
                    float(sum(raw.count(token) for token in [";", "|", "&", "`", "$"])),
                    float(len(TRAVERSAL_RE.findall(text))),
                    float(len(HTML_JS_RE.findall(text))),
                    float(len(SQL_RE.findall(text))),
                    float(len(SHELL_RE.findall(text))),
                ]
            )
        return np.asarray(rows, dtype=float)
