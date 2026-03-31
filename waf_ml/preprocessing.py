import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass
from typing import Iterable, List
from urllib.parse import unquote_plus


BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
WHITESPACE_RE = re.compile(r"\s+")
SEPARATOR_RE = re.compile(r"\s*([;|`])\s*")
AMPERSAND_RE = re.compile(r"\s*&\s*")


@dataclass(frozen=True)
class NormalizedPayload:
    raw: str
    normalized: str

    @property
    def combined(self) -> str:
        return f"__raw__ {self.raw}\n__normalized__ {self.normalized}"


def coerce_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return str(value)


def _looks_like_base64(value: str) -> bool:
    stripped = value.strip()
    if len(stripped) < 12 or len(stripped) % 4 != 0:
        return False
    return bool(BASE64_RE.fullmatch(stripped))


def repeated_url_decode(value: str, max_depth: int = 2) -> str:
    current = value
    for _ in range(max_depth):
        decoded = unquote_plus(current)
        if decoded == current:
            break
        current = decoded
    return current


def repeated_base64_decode(value: str, max_depth: int = 2) -> str:
    current = value.strip()
    for _ in range(max_depth):
        if not _looks_like_base64(current):
            break
        try:
            decoded = base64.b64decode(current, validate=True).decode(
                "utf-8", errors="ignore"
            )
        except (binascii.Error, ValueError):
            break
        if not decoded or decoded == current:
            break
        current = decoded
    return current


def normalize_token(value: object, *, lowercase: bool = True) -> str:
    text = coerce_text(value)
    text = unicodedata.normalize("NFKC", text)
    text = text.replace("\x00", " ")
    text = repeated_url_decode(text)
    text = repeated_base64_decode(text)
    text = text.replace("\\", "/")
    text = text.replace("&&", " && ").replace("||", " || ")
    text = SEPARATOR_RE.sub(r" \1 ", text)
    text = AMPERSAND_RE.sub("&", text)
    text = WHITESPACE_RE.sub(" ", text).strip()
    if lowercase:
        text = text.lower()
    return text


def normalize_payload(payload: object) -> NormalizedPayload:
    raw = coerce_text(payload).strip()
    if not raw:
        return NormalizedPayload(raw="", normalized="")

    if "&" in raw or "=" in raw:
        normalized_fields: List[str] = []
        for field in raw.split("&"):
            if "=" in field:
                key, value = field.split("=", 1)
                normalized_fields.append(
                    f"{normalize_token(key)}={normalize_token(value)}"
                )
            else:
                normalized_fields.append(normalize_token(field))
        normalized = "&".join(part for part in normalized_fields if part)
    else:
        normalized = normalize_token(raw)
    return NormalizedPayload(raw=raw, normalized=normalized)


def combine_raw_and_normalized(payloads: Iterable[object]) -> List[str]:
    return [normalize_payload(payload).combined for payload in payloads]
