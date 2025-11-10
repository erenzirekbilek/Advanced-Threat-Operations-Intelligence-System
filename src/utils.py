# src/utils.py
"""
Yardımcı (utility) fonksiyonlar ve küçük yardımcı sınıflar
- Zaman/parsing, dosya IO, logger, basit rate limiter
- SQLAlchemy model -> dict dönüşümü
- Güvenli erişim/convert yardımcıları
"""

from __future__ import annotations

import os
import json
import logging
import socket
import functools
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple, TypeVar

T = TypeVar("T")

# -------------------------
# File / path helpers
# -------------------------
def ensure_output_dir(path: str) -> str:
    """Ensure directory exists and return absolute path."""
    os.makedirs(path, exist_ok=True)
    return os.path.abspath(path)


def write_json_file(obj: Any, path: str, indent: int = 2) -> None:
    """Write JSON to disk in UTF-8 safely (atomic write minimal)."""
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=indent, ensure_ascii=False, default=str)
    os.replace(tmp, path)


def load_json_file(path: str, default: Any = None) -> Any:
    """Load JSON file, return default on error."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


# -------------------------
# Time / parsing helpers
# -------------------------
def current_utc() -> datetime:
    """Return current UTC datetime (tz-aware)."""
    return datetime.now(timezone.utc)


def parse_iso_ts(value: str) -> datetime:
    """Parse common ISO datetime strings. Raises ValueError on bad input."""
    # datetime.fromisoformat supports many formats but ensure UTC handling
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        # assume UTC if no tz provided
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# -------------------------
# Networking helpers
# -------------------------
def is_valid_ip(ip: Optional[str]) -> bool:
    """Return True if string is valid IPv4 or IPv6 address (basic)."""
    if not ip:
        return False
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except OSError:
            return False


def mask_ip(ip: Optional[str]) -> Optional[str]:
    """Return masked IP for safe logging (IPv4 -> 192.0.2.xxx)."""
    if not ip:
        return None
    try:
        # IPv4
        parts = ip.split(".")
        if len(parts) == 4:
            parts[-1] = "0"
            return ".".join(parts)
        # IPv6: show only prefix
        chunks = ip.split(":")
        if len(chunks) >= 2:
            return ":".join(chunks[:2]) + "::"
    except Exception:
        pass
    return None


# -------------------------
# SQLAlchemy helpers
# -------------------------
def model_to_dict(obj: Any, include: Optional[List[str]] = None, exclude: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Convert SQLAlchemy model instance into a serializable dict.
    - include: list of attribute names to include (if provided)
    - exclude: list of attribute names to exclude
    """
    exclude = set(exclude or [])
    result: Dict[str, Any] = {}
    for col in getattr(obj.__class__, "__table__", []).columns if hasattr(obj.__class__, "__table__") else []:
        name = col.name
        if include and name not in include:
            continue
        if name in exclude:
            continue
        value = getattr(obj, name, None)
        # Convert datetime to isoformat for JSON friendliness
        if isinstance(value, datetime):
            value = value.isoformat()
        result[name] = value
    # Fallback: if __table__ absent, try __dict__
    if not result and hasattr(obj, "__dict__"):
        for k, v in obj.__dict__.items():
            if k.startswith("_"):
                continue
            if include and k not in include:
                continue
            if k in exclude:
                continue
            if isinstance(v, datetime):
                v = v.isoformat()
            result[k] = v
    return result


# -------------------------
# Logging setup
# -------------------------
def setup_logger(name: str = "esip", level: int = logging.INFO, logfile: Optional[str] = None) -> logging.Logger:
    """Return configured logger. If logfile provided, add FileHandler."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger  # already configured
    logger.setLevel(level)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    if logfile:
        fh = logging.FileHandler(logfile, encoding="utf-8")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    return logger


# -------------------------
# Safe conversion helpers
# -------------------------
def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


# -------------------------
# Iteration / chunking / batching
# -------------------------
def chunked_iterable(iterable: Iterable[T], size: int) -> Iterator[List[T]]:
    """Yield successive chunks (lists) from iterable."""
    chunk: List[T] = []
    for item in iterable:
        chunk.append(item)
        if len(chunk) >= size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


# -------------------------
# Rate limiter (in-memory, simple)
# -------------------------
class SimpleRateLimiter:
    """
    Very small sliding-window rate limiter (per-key).
    Usage:
      limiter = SimpleRateLimiter(max_calls=10, window_seconds=60)
      if limiter.allow('192.0.2.1'): ...
    Note: not distributed, intended for local dev/testing.
    """

    def __init__(self, max_calls: int, window_seconds: int):
        self.max_calls = int(max_calls)
        self.window = int(window_seconds)
        self._calls: Dict[Any, List[float]] = {}

    def allow(self, key: Any) -> bool:
        now = time.time()
        calls = self._calls.setdefault(key, [])
        # remove expired
        while calls and calls[0] <= now - self.window:
            calls.pop(0)
        if len(calls) < self.max_calls:
            calls.append(now)
            return True
        return False


# -------------------------
# Retry decorator
# -------------------------
def retry_on_exception(max_attempts: int = 3, wait_seconds: float = 0.5, exceptions: Tuple[type, ...] = (Exception,)):
    """
    Decorator to retry function on exception.
    """
    def deco(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            last_exc = None
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as exc:
                    last_exc = exc
                    if attempt < max_attempts:
                        time.sleep(wait_seconds)
                    else:
                        raise
            # fallback (shouldn't reach)
            if last_exc:
                raise last_exc
        return wrapper
    return deco


# -------------------------
# Misc helpers
# -------------------------
def first_not_none(*values: Any) -> Any:
    """Return first non-None value or None."""
    for v in values:
        if v is not None:
            return v
    return None
