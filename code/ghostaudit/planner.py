"""Turn reconstructed per-resource state into status + ordered steps (deterministic)."""
from __future__ import annotations

from .schema import finalize, make_step
from .state import (Item, ST_PRESENT_PII, ST_PRESENT_CLEAN, ST_ABSENT, ST_ACTIVE,
                    ST_BLOCKED)


def _treatment(item: Item, policy) -> str:
    rule = policy.match(item.category)
    if rule is None:
        return "DELETE"
    return rule.treatment


def plan(items: list[Item], policy, deleted_resources: set | None = None) -> tuple[str, list[dict]]:
    find, rem, ver = [], [], []
    for it in items:
        s, r = it.system_id, it.resource_id
        ev = it.evidence_id if it.verified else ""
        t = _treatment(it, policy)
        if deleted_resources and (s, r) in deleted_resources and it.kind == "record":
            t = "DELETE"
        if it.kind == "flow":
            if it.state == ST_ACTIVE:
                find.append(make_step("REPORT_ACTIVE_DATA_FLOW", s, r, ev))
                rem.append(make_step("DISABLE_DATA_FLOW", s, r))
            ver.append(make_step("VERIFY_DATA_FLOW_DISABLED", s, r, ev))
        elif it.kind == "restore":
            if it.state == ST_ACTIVE:
                find.append(make_step("REPORT_RESTORE_RISK", s, r, ev))
                rem.append(make_step("BLOCK_RESTORE", s, r))
            ver.append(make_step("VERIFY_RESTORE_BLOCKED", s, r, ev))
        elif t == "DELETE":
            if it.state != ST_ABSENT:
                # records that expose direct identifiers get REPORT_REMAINING_RECORD;
                # residual rows that no longer expose identifiers but must still be
                # removed (clean contact/log copies) are reported the same way
                find.append(make_step("REPORT_REMAINING_RECORD", s, r, ev))
                rem.append(make_step("DELETE_RECORD", s, r))
            ver.append(make_step("VERIFY_RECORD_ABSENT", s, r, ev))
        elif t == "ANONYMIZE":
            if it.state == ST_ABSENT:
                continue
            if it.state == ST_PRESENT_PII:
                find.append(make_step("REPORT_EXPOSED_PII", s, r, ev))
                rem.append(make_step("ANONYMIZE_RECORD", s, r))
            ver.append(make_step("VERIFY_RECORD_ANONYMIZED", s, r, ev))
        elif t == "REDACT":
            if it.state == ST_ABSENT:
                continue
            if it.state == ST_PRESENT_PII:
                find.append(make_step("REPORT_EXPOSED_PII", s, r, ev))
                rem.append(make_step("REDACT_RECORD", s, r))
            ver.append(make_step("VERIFY_RECORD_REDACTED", s, r, ev))
        elif t == "RETAIN":
            if it.state == ST_ABSENT:
                continue
            if it.state == ST_PRESENT_PII:
                find.append(make_step("REPORT_EXPOSED_PII", s, r, ev))
                rem.append(make_step("REDACT_RECORD", s, r))
                ver.append(make_step("VERIFY_RECORD_REDACTED", s, r, ev))
            ver.append(make_step("VERIFY_RECORD_PRESENT", s, r, ev))
    if find:
        for st in rem + ver:
            st["evidence_id"] = ""   # proposed / future steps carry no evidence id
        return "INCOMPLETE", finalize(find + rem + ver)
    return "COMPLETE", finalize(ver)
