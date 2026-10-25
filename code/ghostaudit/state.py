"""Reconstruct per-resource state at audit_at from evidence files + system_activity.

Evidence model (reverse-engineered from the real dataset formats):
- every evidence record is normalised to (system_id, resource_id, obs_time, payload)
- system_id comes from the *content* (service=... keys, data_store / origin_system
  fields, table names) never from the file name or manifest origin;
- a resource belongs to a user when the record or a sibling lookup carries any of
  the user's identifiers (current/historical emails, phones, hashes, user_id, name);
- the account/profile resource id is resolved through evidence records that pair it
  with one of the user's identifiers, never by guessing;
- point-in-time snapshots (sql dumps, snapshot bundles, service exports, readback
  logs, handover lists, observability logs) say FOUND / NOT_FOUND / REDACTED /
  ANONYMIZED / ACTIVE / BLOCKED for each resource at their capture time; the newest
  admissible observation wins.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime

from .common import Cols, parse_ts
from .identity import DIRECT, Identity

# canonical category per system prefix -> (rule category, kind)
SYSTEM_CATEGORY = {
    "account_service": ("USER_PROFILE", "record"),
    "identity_service": ("ACCOUNT_TOMBSTONE", "record"),
    "search_service": ("SEARCH_INDEX_ENTRY", "record"),
    "support_platform": ("SUPPORT_MESSAGE", "record"),
    "analytics_platform": ("ANALYTICS_PROFILE", "record"),
    "export_service": ("USER_EXPORT", "record"),
    "integration_service": ("DATA_FLOW", "flow"),
    "backup_service": ("BACKUP_ARCHIVE", "restore"),
    "security_service": ("SECURITY_AUDIT_LOG", "record"),
    "marketing_platform": ("MARKETING_PROFILE", "record"),
    "legal_service": ("LEGAL_HOLD_RECORD", "record"),
    "object_storage": ("SUPPORT_ATTACHMENT", "record"),
    "downstream_delivery_service": ("EMAIL_DELIVERY_LOG", "record"),
}

# states a resource can be in at observation time
ST_PRESENT_PII = "PRESENT_PII"      # exists and exposes direct identifiers
ST_PRESENT_CLEAN = "PRESENT_CLEAN"  # exists; no direct identifiers (redacted/anonymised)
ST_ABSENT = "ABSENT"                # confirmed not found
ST_ACTIVE = "ACTIVE"                # flow enabled / restore possible
ST_BLOCKED = "BLOCKED"              # flow disabled / restore blocked


@dataclass
class Obs:
    """One timestamped observation of a resource."""
    ts: datetime            # record-level observation time (ordering within a file)
    file_ts: datetime       # manifest capture time of the file (admissibility)
    file_id: str            # evidence file_id or activity_id
    state: str              # ST_*
    pii: set = field(default_factory=set)   # direct identifiers seen in payload
    has_ref: bool = False                   # payload carries the stable user_id
    order: int = 0


@dataclass
class Item:
    kind: str            # record | flow | restore
    system_id: str
    resource_id: str
    category: str
    state: str           # ST_* at audit_at
    evidence_id: str     # evidence proving the state ("" if only claimed)
    pii: set = field(default_factory=set)
    has_ref: bool = False
    verified: bool = False  # state proven by direct observation (not a claim)


class ResourceWorld:
    """All observations indexed by (system, resource)."""

    def __init__(self):
        self.obs: dict[tuple, list[Obs]] = defaultdict(list)
        self.res_tokens: dict[tuple, set] = defaultdict(set)  # tokens ever seen with the resource
        self.cat_hints: dict[tuple, str] = {}
        self.order = 0

    def add(self, system, resource, ts, file_ts, file_id, state, pii=(), has_ref=False,
            tokens=(), cat_hint=""):
        if not system or not resource or ts is None or file_ts is None:
            return
        key = (system, resource)
        self.order += 1
        self.obs[key].append(Obs(ts, file_ts, file_id, state, set(pii), has_ref, self.order))
        if cat_hint:
            self.cat_hints[key] = cat_hint
        self.res_tokens[key] |= {t for t in tokens if t}

    def state_at(self, key, audit_at):
        obs = [o for o in self.obs.get(key, []) if o.file_ts <= audit_at]
        if not obs:
            return None
        obs.sort(key=lambda o: (o.file_ts, o.ts, o.order))
        return obs[-1]

    def keys_for(self, ident: Identity, audit_at):
        """Resources whose admissible observations ever carried a user identifier."""
        toks = ident.lookup_tokens() | {n for n in ident.names if len(n) >= 5}
        out = set()
        for key, toks_seen in self.res_tokens.items():
            if any(o.file_ts <= audit_at for o in self.obs[key]):
                if toks & toks_seen:
                    out.add(key)
        return out


def categorize(system_id: str, resource_id: str) -> tuple[str, str]:
    cat, kind = SYSTEM_CATEGORY.get(system_id, ("", "record"))
    if not cat:
        pref = (resource_id or "").split("_")[0]
        cat = {
            "account": "USER_PROFILE", "tombstone": "ACCOUNT_TOMBSTONE",
            "search": "SEARCH_INDEX_ENTRY", "support": "SUPPORT_MESSAGE",
            "analytics": "ANALYTICS_PROFILE", "export": "USER_EXPORT",
            "data": "DATA_FLOW", "backup": "BACKUP_ARCHIVE",
            "audit": "SECURITY_AUDIT_LOG", "marketing": "MARKETING_PROFILE",
            "object": "SUPPORT_ATTACHMENT",
        }.get(pref, "")
        kind = "flow" if pref == "data" else "restore" if pref == "backup" else "record"
    return cat, kind


class Activity:
    """system_activity.csv: claims used only to NAME the primary profile resource."""

    def __init__(self, rows, overrides=None):
        from .common import Cols, parse_ts
        self.rows = []
        self.deleted_resources: set[tuple] = set()  # (target_system, resource) the
        # deletion workflow itself treated with DELETE_RECORD (treatment hint)
        for r in rows:
            et = r.get("event_type") or r.get("operation") or ""
            if et != "DELETE_RECORD":
                continue
            tgt = r.get("target_system") or ""
            self.deleted_resources.add((tgt, r.get("resource_id") or ""))
            if tgt != "account_service":
                continue
            self.rows.append({"ts": parse_ts(r.get("event_time") or r.get("timestamp")),
                              "rid": r.get("resource_id") or ""})

    def account_resource(self, ident: Identity, audit_at: datetime,
                         requested_at: str, reported_at: str) -> str:
        hi = parse_ts(reported_at) or audit_at
        lo = parse_ts(requested_at)
        if lo is None:
            lo = hi
        window = [a for a in self.rows if a["ts"] and a["rid"]
                  and abs((a["ts"] - hi).total_seconds()) <= 3 * 86400
                  and a["ts"] >= lo.replace(hour=0, minute=0, second=0)]
        if not window:
            return ""
        window.sort(key=lambda a: abs((a["ts"] - hi).total_seconds()))
        return window[0]["rid"]


def build_items(ident: Identity, world: ResourceWorld, audit_at: datetime,
                warn: list) -> list[Item]:
    """Resolve the user's resource universe and its state at audit_at."""
    items = []
    for key in sorted(world.keys_for(ident, audit_at)):
        system, resource = key
        cat, kind = categorize(system, resource)
        hint = world.cat_hints.get(key, "")
        if hint == "attachment":
            cat, kind = "SUPPORT_ATTACHMENT", "record"
        if not cat:
            warn.append(f"uncategorised resource {key}")
            continue
        last = world.state_at(key, audit_at)
        items.append(Item(kind, system, resource, cat, last.state, last.file_id,
                          last.pii, last.has_ref, verified=True))
    return items
