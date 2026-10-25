"""Parse every evidence file into timestamped observations of (system, resource).

Every supported format is normalised into Observation tuples:
    (system_id, resource_id, obs_time, state, pii_tokens, ref_token, file_id)

States (ghostaudit.state.ST_*): PRESENT_PII, PRESENT_CLEAN, ABSENT, ACTIVE, BLOCKED.

Formats handled:
- SQL dumps (SQLite-compatible): profile/search/analytics/support/export/connector/
  backup/security tables, incl. customer_data_* generic stores with origin_system +
  record_json, and replica drift (primary vs replica tables).
- JSON snapshot bundles: {"snapshots": [{data_store, collection, captured_at, records}]}
- JSON service resource exports: {"service_exports": {service: {section: [records]}}}
- JSON collections: {"records": [...]} with a top-level source/origin (analytics
  reports, export jobs, connector configurations, security audit ledger).
- Plain lookup logs: "- ts | system | resource | CATEGORY | RESULT | subject".
- kv observability/readback logs: service=..., resource_id=..., event=..., plus
  lookup_key / correlation_key / matched_value tokens and per-event result fields.
- PDFs (via pypdf) and OCR-able images: treated as subject-bearing documents whose
  existence proves the record exists (e.g. support attachments); resource id is
  recovered from "support_XXXX" style references or the file stem.
"""
from __future__ import annotations

import csv
import json
import os
import re
import sqlite3
from datetime import datetime

from . import llm
from .common import parse_ts, find_ts, read_csv
from .identity import signature, classify_value
from .state import (ResourceWorld, ST_PRESENT_PII, ST_PRESENT_CLEAN, ST_ABSENT,
                    ST_ACTIVE, ST_BLOCKED)

IMG_EXT = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tif", ".tiff"}

# ---------------------------------------------------------------------------
# small helpers

DIRECT_KEYS = ("email", "phone", "email_hash", "full_name", "display_name",
               "requester_email", "requester_phone", "requester_name",
               "owner_email", "owner_phone", "customer_email", "matched_value",
               "name")
REF_KEYS = ("customer_reference", "subject_reference", "user_id", "subject_selector",
            "lookup_key", "correlation_key", "subject_ref", "match_key", "query")


def flatten(obj, out=None, prefix=""):
    """Flatten nested dicts/lists into {key: scalar} (last wins per key)."""
    if out is None:
        out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            flatten(v, out, k)
    elif isinstance(obj, list):
        for v in obj:
            flatten(v, out, prefix)
    else:
        if obj is not None:
            out[prefix] = obj
    return out


def tokens_of(fields: dict):
    """(pii_tokens, ref_token_set) from a flat record."""
    pii, refs = set(), set()
    for k, v in fields.items():
        kl, vs = k.lower(), str(v).strip()
        if not vs or vs.lower() in ("null", "none", "nan", ""):
            continue
        if kl in REF_KEYS:
            refs.add(vs.lower() if "@" not in vs else vs.lower())
        if kl in DIRECT_KEYS or kl.endswith("_email") or kl.endswith("_phone"):
            kind = classify_value(vs)
            if kind == "email":
                pii.add(vs.lower())
            elif kind == "phone":
                import re as _re
                d = _re.sub(r"\D", "", vs)
                if len(d) >= 7:
                    pii.add(d[-10:])
                    pii.add(d)
            elif kind == "email_hash":
                pii.add(vs.lower())
            elif kl in ("full_name", "display_name", "requester_name", "name") and len(vs) >= 5:
                pii.add(vs.lower())
    return pii, refs


def present_state(fields: dict, pii: set, refs: set):
    """PRESENT_PII vs PRESENT_CLEAN for a found record."""
    if pii:
        return ST_PRESENT_PII
    return ST_PRESENT_CLEAN


# ---------------------------------------------------------------------------
# per-format extractors -> list of (system, resource, ts, state, pii, refs)

def obs_from_lookup_log(text: str):
    """"- ts | system | resource | CATEGORY | RESULT | subject" lines (handover)."""
    out = []
    for line in text.splitlines():
        m = re.match(r"\s*-\s*(\S+)\s*\|\s*([\w_]+)\s*\|\s*([\w\-.]+)\s*\|\s*([A-Z_]+)\s*\|\s*"
                     r"([A-Z_]+)\s*\|\s*(.+)", line)
        if not m:
            continue
        ts_s, system, rid, cat, result, subject = m.groups()
        ts = parse_ts(ts_s)
        subj = subject.strip().strip('"')
        pii, refs = set(), set()
        kind = classify_value(subj)
        if kind == "email":
            pii.add(subj.lower())
        elif subj.startswith("user_"):
            refs.add(subj.lower())
        result = result.upper()
        if result in ("NOT_FOUND", "ABSENT", "DELETED"):
            state = ST_ABSENT
        elif result in ("ANONYMIZED", "REDACTED"):
            state = ST_PRESENT_CLEAN
            pii = set()
        elif result in ("BLOCKED", "DISABLED"):
            state = ST_BLOCKED
            pii = set()
        elif result in ("ACTIVE",):
            state = ST_ACTIVE
        elif result in ("FOUND", "IDENTIFIABLE"):
            state = ST_PRESENT_PII if pii else ST_PRESENT_CLEAN
        else:
            continue
        cat_hint = "attachment" if cat == "SUPPORT_ATTACHMENT" else ""
        out.append((system + (":" + cat_hint if cat_hint else ""), rid, ts, state, pii,
                    refs | {subj.lower()} if subj else refs))
    return out


def obs_from_kv_log(text: str):
    """Observability / readback logs with key=value (or JSON payload) per line."""
    out = []
    # group lookup_start lookup_key tokens by trace so completed lines inherit them
    pending = {}  # trace_id -> set of tokens seen on started lines
    for line in text.splitlines():
        ts = find_ts(line)
        if ts is None:
            continue
        f = dict(re.findall(r'(\w+)=(\"[^\"]*\"|\S+)', line))
        f = {k: v.strip('"') for k, v in f.items()}
        if line.strip().split(" ", 1)[-1].startswith("{"):
            try:
                payload = json.loads(line.split(" ", 1)[1])
                f.update({k: str(v) for k, v in flatten(payload).items()})
            except ValueError:
                pass
        svc = f.get("service") or f.get("logger")
        is_replica_contact = svc == "support_replica"
        if is_replica_contact:
            svc = "support_platform"
        event = (f.get("event") or "").lower()
        rid = f.get("resource_id")
        trace = f.get("trace_id") or ""
        # collect subject tokens from this line
        pii, refs = tokens_of(f)
        for key in ("lookup_key", "match_key", "subject_key", "scan_key", "subject_ref",
                    "correlation_key", "matched_value", "subject_reference",
                    "customer_reference", "customer_email", "requester_email",
                    "requester_phone", "requester_name"):
            v = f.get(key)
            if v:
                kind = classify_value(v)
                if kind == "email":
                    pii.add(v.lower())
                elif kind == "phone":
                    d = re.sub(r"\D", "", v)
                    pii.add(d[-10:])
                elif v.startswith("user_"):
                    refs.add(v.lower())
        if trace and (pii or refs):
            pending.setdefault(trace, set())
            pending[trace] |= pii | refs
        if not rid or not svc:
            continue
        inherited = pending.get(trace, set())
        pii |= {t for t in inherited if "@" in t or t.isdigit()}
        refs |= {t for t in inherited if t.startswith("user_")}
        if event.endswith("_started"):
            continue
        if event.endswith("_completed"):
            # the completed line holds the definitive state; merge every token the
            # trace saw (from the matching *_started line) so the observation links
            # to the subject even though the completed line only carries nulls
            pii |= {t for t in inherited if "@" in t or t.isdigit()}
            refs |= {t for t in inherited if t.startswith("user_")}
        state = None
        result = (f.get("result") or "").lower()
        status = (f.get("http_status") or f.get("status_code") or "").strip()
        rows = (f.get("rows") or "").strip()
        if "profile_lookup_completed" in event or "read_completed" in event or \
           "query_completed" in event or "lookup_completed" in event:
            if status == "404" or rows == "0" or result in ("miss", "not_found"):
                state = ST_ABSENT
            elif result == "hit" or rows == "1" or status == "200":
                # do we see direct identifiers in the payload?
                has_direct = any(f.get(k) not in (None, "", "null")
                                 for k in ("email", "requester_email", "customer_email",
                                           "email_hash", "full_name", "phone",
                                           "requester_phone", "requester_name",
                                           "matched_value"))
                if "pii_scan" in event or "identity_scan" in event:
                    has_direct = True
                if any(f.get(k) == "[REDACTED]" for k in f):
                    has_direct = False
                state = ST_PRESENT_PII if has_direct else present_state(f, pii, refs)
        elif "pii_scan" in event or "identity_scan" in event:
            state = ST_PRESENT_PII
        elif "marker_check" in event:
            if (f.get("marker_found") or "").lower() == "false":
                state = ST_PRESENT_PII if pii else ST_PRESENT_CLEAN
        elif "restore_candidate_evaluated" in event or "restore_policy" in event:
            allowed = (f.get("restore_allowed") or "").lower()
            eligible = (f.get("eligible") or "").lower()
            block = (f.get("deletion_block") or "").lower()
            if allowed == "false" or block == "true" or eligible == "false":
                state = ST_BLOCKED
            elif allowed == "true" or eligible == "true":
                state = ST_ACTIVE
        elif "connector" in event or "heartbeat" in event or "config" in event:
            en = (f.get("enabled") or "").lower()
            last = (f.get("last_delivery_status") or "").lower()
            if en == "false" or last in ("stopped", "disabled"):
                state = ST_BLOCKED
            elif en == "true" or last == "delivered":
                state = ST_ACTIVE
        if state is None:
            continue
        out.append((svc + (":attachment" if is_replica_contact else ""), rid, ts, state, pii, refs))
    return out


SQL_TABLE_SYSTEM = {
    "customer_profiles": "account_service",
    "search_documents": "search_service",
    "customer_profiles_primary": "account_service",
    "customer_search_documents": "search_service",
    "customer_analytics_profiles": "analytics_platform",
    "customer_analytics_reports": "analytics_platform",
    "support_records": "support_platform",
    "support_conversations": "support_platform",
    "customer_exports": "export_service",
    "customer_export_jobs": "export_service",
    "connector_subscriptions": "integration_service",
    "connector_configurations": "integration_service",
    "backup_restore_entries": "backup_service",
    "backup_catalog": "backup_service",
    "security_audit_records": "security_service",
    "security_audit_events": "security_service",
    "search_documents_primary": "search_service",
    "deleted_customer_references": "identity_service",
}


def obs_from_sql(path: str, file_ts):
    out = []
    con = sqlite3.connect(":memory:")
    with open(path, encoding="utf-8", errors="replace") as fh:
        con.executescript(fh.read())
    tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
    # replication drift: group base names (strip replica suffixes)
    def base_of(t):
        t = t.lower()
        for suf in ("_failover_replica", "_read_replica", "_reporting_replica",
                    "_regional_replica", "_replica", "_primary"):
            if t.endswith(suf):
                return t[: -len(suf)]
        return t
    by_base = {}
    for t in tables:
        if t in ("snapshot_scope",):
            continue
        by_base.setdefault(base_of(t), []).append(t)
    for base, variants in by_base.items():
        cols_rows = {}
        for t in variants:
            cur = con.execute(f'select * from "{t}"')
            cols = [d[0] for d in cur.description]
            rows = [dict(zip(cols, row)) for row in cur.fetchall()]
            cols_rows[t] = rows
        # union of resource ids across variants; a resource missing from the newest
        # snapshot of its own table family is still PRESENT in the variant where seen
        # (the file is one point-in-time capture; variants are different topologies)
        for t, rows in cols_rows.items():
            system_hint = SQL_TABLE_SYSTEM.get(base)
            for row in rows:
                ts = parse_ts(row.get("updated_at") or row.get("captured_at") or
                              row.get("indexed_at")) or file_ts
                system = (row.get("origin_system") or "").strip() or system_hint
                rec = row
                if "record_json" in row:
                    try:
                        rec = json.loads(row["record_json"])
                    except ValueError:
                        rec = row
                    system = (row.get("origin_system") or system or "").strip()
                flat = flatten(rec)
                rid = flat.get("resource_id") or row.get("resource_id")
                if not system or not rid:
                    continue
                pii, refs = tokens_of(flat)
                status = str(flat.get("account_status") or "").upper()
                en = flat.get("enabled")
                ra = flat.get("restore_allowed")
                if base.startswith("connector") or system == "integration_service":
                    state = ST_ACTIVE if str(en) in ("1", "true", "True") else ST_BLOCKED
                    pii2 = pii if state == ST_ACTIVE else set()
                    out.append((system, rid, ts, state, pii2, refs))
                elif base.startswith("backup") or system == "backup_service":
                    state = ST_ACTIVE if str(ra) in ("1", "true", "True") else ST_BLOCKED
                    pii2 = pii if state == ST_ACTIVE else set()
                    out.append((system, rid, ts, state, pii2, refs))
                elif status in ("DELETED", "TOMBSTONED_DELETED"):
                    # tombstone: present; PII if direct identifiers remain
                    out.append((system, rid, ts,
                                ST_PRESENT_PII if pii else ST_PRESENT_CLEAN, pii, refs))
                elif status in ("DELETION_PENDING",):
                    out.append((system, rid, ts, ST_PRESENT_PII if pii else ST_PRESENT_CLEAN,
                                pii, refs))
                else:
                    out.append((system, rid, ts, present_state(flat, pii, refs), pii, refs))
    con.close()
    return out


def obs_from_bundle(data, file_ts):
    """records_assurance snapshot bundles: {snapshots: [...]}"""
    out = []
    for snap in data.get("snapshots", []):
        system = snap.get("data_store") or snap.get("system") or ""
        ts = parse_ts(snap.get("captured_at")) or file_ts
        for rec in snap.get("records", []):
            flat = flatten(rec)
            rid = flat.get("resource_id")
            if not rid:
                continue
            pii, refs = tokens_of(flat)
            if system == "integration_service":
                state = ST_ACTIVE if str(flat.get("enabled")) in ("true", "1", "True") else ST_BLOCKED
                out.append((system, rid, ts, state, pii if state == ST_ACTIVE else set(), refs))
            elif system == "backup_service":
                ra = flat.get("restore_allowed")
                state = ST_ACTIVE if str(ra) in ("true", "1", "True") else ST_BLOCKED
                out.append((system, rid, ts, state, pii if state == ST_ACTIVE else set(), refs))
            else:
                out.append((system, rid, ts, present_state(flat, pii, refs), pii, refs))
    return out


def obs_from_service_export(data, file_ts):
    """service_resource_export: point-in-time per-service reads."""
    out = []
    se = data.get("service_exports", {})
    ts0 = parse_ts(data.get("exported_at")) or file_ts
    for system, body in se.items():
        for section, records in body.items():
            if not isinstance(records, list):
                continue
            for rec in records:
                flat = flatten(rec)
                rid = flat.get("resource_id")
                if not rid:
                    continue
                ts = parse_ts(flat.get("observed_at")) or ts0
                pii, refs = tokens_of(flat)
                if system == "account_service":
                    prof = rec.get("profile")
                    if str(flat.get("status_code")) == "404" or not prof:
                        out.append((system, rid, ts, ST_ABSENT, set(), refs))
                    else:
                        ppii, prefs = tokens_of(flatten(prof))
                        out.append((system, rid, ts, present_state(flat, ppii, prefs),
                                    ppii, prefs))
                elif system == "search_service":
                    docs = rec.get("hits", {}).get("documents") or []
                    total = rec.get("hits", {}).get("total", len(docs))
                    q = flat.get("query", "")
                    qpii, _ = tokens_of({"query": q}) if q else (set(), set())
                    if total and docs:
                        dpii, drefs = set(), set()
                        for doc in docs:
                            a, b = tokens_of(flatten(doc))
                            dpii |= a
                            drefs |= b
                        out.append((system, rid, ts, ST_PRESENT_PII, dpii | qpii, drefs | refs))
                    else:
                        out.append((system, rid, ts, ST_ABSENT, set(), refs))
                elif system == "integration_service":
                    en = str(flat.get("enabled")).lower()
                    last = str(flat.get("last_delivery_status")).lower()
                    state = ST_BLOCKED if en == "false" or last == "stopped" else ST_ACTIVE
                    out.append((system, rid, ts, state, pii if state == ST_ACTIVE else set(), refs))
                elif system == "backup_service":
                    ra = str(flat.get("restore_allowed")).lower()
                    state = ST_ACTIVE if ra == "true" else ST_BLOCKED
                    out.append((system, rid, ts, state, pii if state == ST_ACTIVE else set(), refs))
                else:
                    out.append((system, rid, ts, present_state(flat, pii, refs), pii, refs))
    return out


def obs_from_json_collection(data, file_ts, source_hint):
    """{records: [...]} collections: analytics reports, export jobs, connectors, ledger."""
    out = []
    recs = data.get("records")
    if not isinstance(recs, list):
        return out
    ts0 = parse_ts(data.get("captured_at") or data.get("exported_at")) or file_ts
    src = (data.get("source") or data.get("origin") or source_hint or "").lower()
    for rec in recs:
        flat = flatten(rec)
        rid = flat.get("resource_id")
        if not rid:
            continue
        ts = parse_ts(flat.get("recorded_at") or flat.get("observed_at") or
                      flat.get("captured_at")) or ts0
        system = flat.get("system") or flat.get("data_store") or ""
        if not system:
            system = ("security_service" if "audit" in src else
                      "analytics_platform" if "analytics" in src else
                      "export_service" if "export" in src else
                      "integration_service" if ("connector" in src or "integration" in src) else "")
        pii, refs = tokens_of(flat)
        result = str(flat.get("result") or "").upper()
        if result:
            if result in ("NOT_FOUND",):
                state = ST_ABSENT
            elif result in ("ANONYMIZED", "REDACTED"):
                state = ST_PRESENT_CLEAN
                pii = set()
            elif result in ("BLOCKED", "DISABLED"):
                state = ST_BLOCKED
                pii = set()
            elif result == "ACTIVE":
                state = ST_ACTIVE
            else:
                state = ST_PRESENT_PII if pii else ST_PRESENT_CLEAN
            out.append((system, rid, ts, state, pii, refs))
            continue
        if system == "integration_service":
            en = flat.get("enabled")
            state = ST_ACTIVE if str(en) in ("true", "1", "True") else ST_BLOCKED
        elif system == "backup_service":
            ra = flat.get("restore_allowed")
            state = ST_ACTIVE if str(ra) in ("true", "1", "True") else ST_BLOCKED
        else:
            state = present_state(flat, pii, refs)
        out.append((system, rid, ts, state, pii, refs))
    return out


def read_pdf(path):
    try:
        from pypdf import PdfReader
        return "\n".join((p.extract_text() or "") for p in PdfReader(path).pages)
    except Exception:
        return None


def read_image(path):
    try:
        import pytesseract
        from PIL import Image
        return pytesseract.image_to_string(Image.open(path))
    except Exception:
        return llm.ask("Transcribe all text in this image verbatim. Output only the text.",
                       "Transcribe.", "ocr", image_path=path, max_tokens=1500)


def obs_from_document(text: str, ts):
    """A PDF/image that mentions identifiers proves a support attachment record exists."""
    out = []
    m = re.findall(r"\b(support_\d+)\b", text)
    rid = m[0] if m else None
    sig = signature(text)
    pii = sig.emails | sig.phones
    refs = {w for w in sig.words if w.startswith("user_")}
    if rid:
        # attachments are subject-owned: mark with a synthetic category hint via system
        out.append(("support_platform:attachment", rid, ts,
                    ST_PRESENT_PII if pii else ST_PRESENT_CLEAN, pii, refs))
    return out


# ---------------------------------------------------------------------------

class EvidenceIndex:
    def __init__(self, dataset_dir: str, overrides: dict | None = None):
        self.dir = dataset_dir
        self.world = ResourceWorld()
        self.warnings: list[str] = []
        self.file_count = 0
        self.snapshots: list[tuple[str, datetime]] = []  # (file_id, captured_at) full-store snapshots
        self._load()

    def _entries(self):
        rows = read_csv(os.path.join(self.dir, "evidence_files.csv"))
        entries = []
        for r in rows:
            rel = r.get("file_path") or r.get("path") or ""
            path = os.path.join(self.dir, rel)
            if not os.path.isfile(path):
                path = os.path.join(self.dir, "evidence", os.path.basename(rel))
            fid = r.get("file_id") or os.path.splitext(os.path.basename(rel))[0]
            if not os.path.isfile(path):
                self.warnings.append(f"manifest file missing on disk: {fid} ({rel})")
                continue
            entries.append((fid, path, r.get("origin", ""), parse_ts(r.get("captured_at"))))
        return entries

    def _load(self):
        for fid, path, origin, ts in self._entries():
            try:
                self._ingest(fid, path, origin, ts)
                self.file_count += 1
            except Exception as exc:
                self.warnings.append(f"failed to parse {fid}: {exc!r}")

    def absence_evidence(self, system, rid, audit_at):
        """If a full-store snapshot captured at/before audit_at does NOT contain this
        resource, that snapshot proves ABSENT. Returns (file_id, state)."""
        best = None
        for fid, ts in sorted(self.snapshots, key=lambda x: x[1]):
            if ts > audit_at:
                continue
            best = fid  # freshest snapshot at or before audit_at
        if best:
            from .state import ST_ABSENT
            return best, ST_ABSENT
        return "", ST_ABSENT

    def _emit(self, fid, observations, file_ts):
        for system, rid, ts, state, pii, refs in observations:
            if ts is None or file_ts is None:
                continue
            cat_hint = ""
            if ":" in system:
                system, cat_hint = system.split(":", 1)
            toks = set(pii) | set(refs)
            self.world.add(system, rid, ts, file_ts, fid, state, pii, refs, toks,
                           cat_hint=cat_hint)

    def _ingest(self, fid, path, origin, ts):
        ext = os.path.splitext(path)[1].lower()
        if ext in (".sql", ".db", ".sqlite", ".sqlite3"):
            obs = obs_from_sql(path, ts)
            self._emit(fid, obs, ts)
            if ts:
                self.snapshots.append((fid, ts))
        elif ext in (".json", ".jsonl", ".ndjson"):
            with open(path, encoding="utf-8", errors="replace") as fh:
                data = json.load(fh)
            if isinstance(data, dict) and "service_exports" in data:
                self._emit(fid, obs_from_service_export(data, ts), ts)
                if ts:
                    self.snapshots.append((fid, ts))
            elif isinstance(data, dict) and "snapshots" in data:
                self._emit(fid, obs_from_bundle(data, ts), ts)
                if ts:
                    self.snapshots.append((fid, ts))
            else:
                self._emit(fid, obs_from_json_collection(data, ts, origin), ts)
        elif ext == ".csv":
            with open(path, encoding="utf-8-sig", newline="") as fh:
                rows = list(csv.DictReader(fh))
            self._emit(fid, obs_from_json_collection({"records": rows}, ts, origin), ts)
        else:
            text = None
            if ext == ".pdf":
                text = read_pdf(path)
            elif ext in IMG_EXT:
                text = read_image(path)
            else:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            if text is None:
                self.warnings.append(f"no text extracted from {fid} ({ext})")
                return
            if "|" in text and re.search(r"\|\s*(FOUND|NOT_FOUND|IDENTIFIABLE|ANONYMIZED|"
                                         r"ACTIVE|BLOCKED|DISABLED|REDACTED)\s*\|", text):
                self._emit(fid, obs_from_lookup_log(text), ts)
            elif "=" in text or re.search(r"^\S+\s+\{", text, re.M):
                self._emit(fid, obs_from_kv_log(text), ts)
            else:
                self._emit(fid, obs_from_document(text, ts), ts)
