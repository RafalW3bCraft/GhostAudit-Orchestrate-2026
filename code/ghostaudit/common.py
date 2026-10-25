"""Shared helpers: timestamps, CSV loading, tolerant column resolution."""
from __future__ import annotations

import csv
import json
import os
import re
from datetime import datetime, timezone

TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?")


def parse_ts(value):
    """Parse many timestamp spellings into naive UTC datetimes (None if unparseable)."""
    if value is None:
        return None
    s = str(value).strip()
    if not s or s.lower() in ("null", "none", "nan", "n/a"):
        return None
    dt = None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d", "%d/%m/%Y %H:%M:%S",
                    "%m/%d/%Y %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
            try:
                dt = datetime.strptime(s, fmt)
                break
            except ValueError:
                continue
    if dt is None:
        return None
    if dt.tzinfo:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def find_ts(text: str):
    m = TS_RE.search(text or "")
    return parse_ts(m.group(0)) if m else None


def read_csv(path: str) -> list[dict]:
    if not path or not os.path.exists(path):
        return []
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return [dict(r) for r in csv.DictReader(fh)]


ALIASES = {
    "requests": {"case_id": ["case_id"], "email": ["email"], "requested_at": ["requested_at"],
                 "reported_status": ["reported_status"], "reported_at": ["reported_at"],
                 "audit_at": ["audit_at"], "request_text": ["request_text", "text", "message"]},
    "identities": {"user_id": ["user_id", "userid", "uid", "id"], "email": ["email", "current_email"],
                   "phone": ["phone", "phone_number", "mobile"],
                   "email_hash": ["email_hash", "email_sha256", "hash"],
                   "name": ["name", "full_name", "display_name"]},
    "audit": {"audit_id": ["audit_id", "log_id", "id"], "user_id": ["user_id", "uid", "subject_id"],
              "field": ["field", "field_name", "attribute", "changed_field"],
              "old": ["old_value", "old", "previous_value", "before"],
              "new": ["new_value", "new", "after"],
              "ts": ["changed_at", "timestamp", "created_at", "at"]},
    "activity": {"activity_id": ["activity_id", "event_id", "id"],
                 "ts": ["timestamp", "occurred_at", "created_at", "at", "ts", "time"],
                 "system_id": ["system_id", "system", "service"],
                 "operation": ["operation", "action", "event_type", "event", "op", "type"],
                 "status": ["status", "result", "outcome", "state"],
                 "resource_id": ["resource_id", "target_id", "target", "job_id", "resource"],
                 "user_id": ["user_id", "subject_id"],
                 "details": ["details", "detail", "message", "description", "notes"]},
    "rules": {"rule_id": ["rule_id", "id"],
              "category": ["data_category", "category", "record_type", "resource_type", "data_type"],
              "system_id": ["system_id", "system", "systems", "applies_to"],
              "treatment": ["required_treatment", "treatment", "required_action", "action", "policy"],
              "allowed": ["allowed_identifiers", "permitted_identifiers", "retained_identifiers",
                          "allowed_fields", "retain_fields"],
              "description": ["description", "notes", "rationale", "reason", "condition"]},
    "manifest": {"file_id": ["file_id", "evidence_id", "id"],
                 "path": ["path", "file_path", "relative_path", "filename", "file_name", "file"],
                 "system_id": ["system_id", "system", "source_system", "service"],
                 "ts": ["captured_at", "snapshot_at", "exported_at", "created_at", "timestamp", "modified_at"],
                 "kind": ["kind", "file_type", "type", "format"]},
}


class Cols:
    """Resolve logical column names against whatever headers the CSV actually has."""

    def __init__(self, rows: list[dict], group: str, overrides: dict | None = None):
        headers = list(rows[0].keys()) if rows else []
        lower = {h.strip().lower(): h for h in headers}
        self.map = {}
        for logical, names in ALIASES[group].items():
            ov = (overrides or {}).get(group, {}).get(logical)
            cands = ([ov] if ov else []) + names
            self.map[logical] = next((lower[c.lower()] for c in cands if c.lower() in lower), None)
        self.headers = headers

    def get(self, row: dict, logical: str, default: str = "") -> str:
        h = self.map.get(logical)
        v = row.get(h) if h else None
        return default if v is None else str(v).strip()


def load_config(path: str | None) -> dict:
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    return {}
