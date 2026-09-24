"""Audit log (SPEC §13): one JSON line per request in data/audit/YYYY-MM-DD.jsonl (UTC date).

- Keys starting with `raw_` (at any depth) are dropped unless LOG_RAW_CONTENT=true, so callers can put
  raw text under `raw_*` keys and let this module decide. Everything else must already be redacted.
- Audit ids are time-sortable (`<ms since epoch, 12 hex>-<8 random hex>`), so ids sort in creation order.
- The JSONL helpers here (`to_jsonable`, `jsonl_append`, `jsonl_read`) are shared with firewall/learning/.
"""
from __future__ import annotations

import dataclasses
import json
import os
import re
import secrets
import threading
import time
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

INDEX_SIZE = 5000
_FILE = re.compile(r"^(\d{4}-\d{2}-\d{2})\.jsonl$")
_MAX_DEPTH = 32


def new_audit_id() -> str:
    """Time-sortable id: f"{ms_since_epoch:012x}-{8 random hex}"."""
    return f"{time.time_ns() // 1_000_000:012x}-{secrets.token_hex(4)}"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def to_jsonable(obj: Any, *, drop_raw: bool = False, _depth: int = 0) -> Any:
    """Plain JSON types: pydantic models / dataclasses become dicts, sets sorted lists, bytes a size
    marker (raw binary never reaches disk). drop_raw removes `raw_*` keys at any depth."""
    if _depth > _MAX_DEPTH:
        return "<max depth>"
    d = _depth + 1
    if obj is None or isinstance(obj, (str, bool, int, float)):
        return obj
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v, drop_raw=drop_raw, _depth=d) for k, v in obj.items()
                if not (drop_raw and str(k).startswith("raw_"))}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(v, drop_raw=drop_raw, _depth=d) for v in obj]
    if isinstance(obj, (set, frozenset)):
        items = [to_jsonable(v, drop_raw=drop_raw, _depth=d) for v in obj]
        try:
            return sorted(items)
        except TypeError:
            return items
    if isinstance(obj, (bytes, bytearray)):
        return f"<{len(obj)} bytes>"
    if hasattr(obj, "model_dump"):
        return to_jsonable(obj.model_dump(mode="json"), drop_raw=drop_raw, _depth=d)
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return to_jsonable(dataclasses.asdict(obj), drop_raw=drop_raw, _depth=d)
    return str(obj)


def jsonl_append(path: Path, obj: dict) -> str:
    """Append one JSON line; returns the line. Lone surrogates are written as \\uXXXX escapes (lossless),
    and a torn last line from a crash is terminated first so it can't swallow this record."""
    line = json.dumps(obj, ensure_ascii=False, default=str)
    data = (line + "\n").encode("utf-8", "backslashreplace")
    with open(path, "a+b") as f:
        f.seek(0, os.SEEK_END)
        if f.tell() > 0:
            f.seek(-1, os.SEEK_END)
            if f.read(1) != b"\n":
                data = b"\n" + data
        f.write(data)
    return line


def jsonl_read(path: Path) -> list[dict]:
    """All parseable dict lines, in file order (corrupt or torn lines are skipped)."""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return []
    out = []
    for line in text.split("\n"):          # not splitlines(): U+2028 etc. may sit inside JSON strings
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out


class AuditLog:
    def __init__(self, settings: Any, *, index_size: int = INDEX_SIZE) -> None:
        self.settings = settings
        self.dir = Path(settings.audit_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self._index_size = index_size
        self._index: OrderedDict[str, tuple[str, str]] = OrderedDict()   # audit_id -> (day, json line)
        self._lock = threading.Lock()

    def _files(self) -> list[Path]:
        """Audit files, newest first."""
        try:
            return sorted((p for p in self.dir.iterdir() if _FILE.match(p.name)), key=lambda p: p.name, reverse=True)
        except FileNotFoundError:
            return []

    def write(self, record: dict) -> str:
        """Append one record; adds `ts` (ISO UTC) and `audit_id` when missing. Returns the audit id."""
        now = datetime.now(timezone.utc)
        rec = to_jsonable(dict(record), drop_raw=not self.settings.LOG_RAW_CONTENT)
        if not rec.get("audit_id"):
            rec["audit_id"] = new_audit_id()
        if not rec.get("ts"):
            rec["ts"] = now.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        day = now.strftime("%Y-%m-%d")
        audit_id = str(rec["audit_id"])
        with self._lock:
            line = jsonl_append(self.dir / f"{day}.jsonl", rec)
            self._index[audit_id] = (day, line)
            self._index.move_to_end(audit_id)
            while len(self._index) > self._index_size:
                self._index.popitem(last=False)
        return audit_id

    def get(self, audit_id: str) -> dict | None:
        """In-memory index (last 5000) first, then the files newest-first (latest line wins)."""
        if not isinstance(audit_id, str) or not audit_id or len(audit_id) > 128:
            return None
        with self._lock:
            hit = self._index.get(audit_id)
        if hit:
            return json.loads(hit[1])
        for path in self._files():
            found = None
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    for line in f:
                        if audit_id not in line:
                            continue
                        try:
                            rec = json.loads(line)
                        except ValueError:
                            continue
                        if isinstance(rec, dict) and rec.get("audit_id") == audit_id:
                            found = rec
            except OSError:
                continue
            if found is not None:
                return found
        return None

    def recent(self, n: int = 50) -> list[dict]:
        """The last n records, newest first."""
        if n <= 0:
            return []
        with self._lock:
            if len(self._index) >= n:
                lines = [line for _, line in list(self._index.values())[-n:]]
                return [json.loads(line) for line in reversed(lines)]
        out: list[dict] = []
        for path in self._files():
            for rec in reversed(jsonl_read(path)):
                out.append(rec)
                if len(out) >= n:
                    return out
        return out

    def purge_old(self) -> int:
        """Delete audit files older than AUDIT_RETENTION_DAYS (<= 0 disables purging). Returns the count."""
        days = int(self.settings.AUDIT_RETENTION_DAYS)
        if days <= 0:
            return 0
        cutoff = (datetime.now(timezone.utc).date() - timedelta(days=days)).isoformat()
        removed = 0
        with self._lock:
            for path in self._files():
                if _FILE.match(path.name).group(1) < cutoff:
                    try:
                        path.unlink()
                        removed += 1
                    except FileNotFoundError:
                        pass
            for audit_id in [a for a, (day, _) in self._index.items() if day < cutoff]:
                del self._index[audit_id]
        return removed


__all__ = ["AuditLog", "new_audit_id", "utc_now_iso", "to_jsonable", "jsonl_append", "jsonl_read"]
