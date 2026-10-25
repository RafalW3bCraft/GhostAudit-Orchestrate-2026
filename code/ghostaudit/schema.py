"""Output contract from problem_statement.md: operations, ordering, validation."""
from __future__ import annotations

import json

STATUSES = ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE")
PHASES = ("FINDING", "REMEDIATION", "VERIFICATION")

# (phase, operation, state) in the canonical order given by the allowed-operations table.
OPERATIONS = [
    ("FINDING", "REPORT_REMAINING_RECORD", "PRESENT"),
    ("FINDING", "REPORT_EXPOSED_PII", "PRESENT"),
    ("FINDING", "REPORT_ACTIVE_DATA_FLOW", "ACTIVE"),
    ("FINDING", "REPORT_RESTORE_RISK", "ACTIVE"),
    ("REMEDIATION", "DISABLE_DATA_FLOW", "DISABLED"),
    ("REMEDIATION", "BLOCK_RESTORE", "BLOCKED"),
    ("REMEDIATION", "DELETE_RECORD", "ABSENT"),
    ("REMEDIATION", "REDACT_RECORD", "REDACTED"),
    ("REMEDIATION", "ANONYMIZE_RECORD", "ANONYMIZED"),
    ("VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT"),
    ("VERIFICATION", "VERIFY_RECORD_PRESENT", "PRESENT"),
    ("VERIFICATION", "VERIFY_RECORD_REDACTED", "REDACTED"),
    ("VERIFICATION", "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
    ("VERIFICATION", "VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
    ("VERIFICATION", "VERIFY_RESTORE_BLOCKED", "BLOCKED"),
]
OP_PHASE = {op: ph for ph, op, _ in OPERATIONS}
OP_STATE = {op: st for _, op, st in OPERATIONS}
OP_RANK = {op: i for i, (_, op, _) in enumerate(OPERATIONS)}
PHASE_RANK = {p: i for i, p in enumerate(PHASES)}
STEP_KEYS = ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id")


def make_step(op: str, system_id: str, resource_id: str, evidence_id: str = "") -> dict:
    return {"phase": OP_PHASE[op], "system_id": system_id, "resource_id": resource_id,
            "operation": op, "state": OP_STATE[op], "evidence_id": evidence_id or ""}


def sort_key(s: dict):
    # phase, then operation order from the table, then system_id, then resource_id ascending
    return (PHASE_RANK[s["phase"]], OP_RANK[s["operation"]], s["system_id"], s["resource_id"])


def finalize(steps: list[dict]) -> list[dict]:
    """De-duplicate, apply the mandated ordering and number steps from 1."""
    seen, out = set(), []
    for s in steps:
        k = (s["operation"], s["system_id"], s["resource_id"])
        if k in seen:
            continue
        seen.add(k)
        out.append(dict(s))
    out.sort(key=sort_key)
    for i, s in enumerate(out, 1):
        s["step_no"] = i
    return [{k: s[k] for k in STEP_KEYS} for s in out]


def validate(status: str, steps: list[dict]) -> list[str]:
    errs = []
    if status not in STATUSES:
        errs.append(f"bad status {status!r}")
    if status == "NOT_APPLICABLE" and steps:
        errs.append("NOT_APPLICABLE must have empty steps")
    for i, s in enumerate(steps, 1):
        if set(s) != set(STEP_KEYS):
            errs.append(f"step {i}: keys {sorted(s)}")
            continue
        if s["step_no"] != i:
            errs.append(f"step {i}: step_no {s['step_no']}")
        op = s["operation"]
        if op not in OP_PHASE:
            errs.append(f"step {i}: unknown op {op}")
            continue
        if s["phase"] != OP_PHASE[op] or s["state"] != OP_STATE[op]:
            errs.append(f"step {i}: phase/state mismatch for {op}")
        if status == "COMPLETE":
            if s["phase"] != "VERIFICATION":
                errs.append(f"step {i}: COMPLETE allows only VERIFICATION")
            if not s["evidence_id"]:
                errs.append(f"step {i}: COMPLETE step needs evidence_id")
        if status == "INCOMPLETE" and s["phase"] != "FINDING" and s["evidence_id"]:
            errs.append(f"step {i}: proposed {s['phase']} step must have empty evidence_id")
    if steps and [sort_key(s) for s in steps] != sorted(sort_key(s) for s in steps):
        errs.append("steps not in mandated order")
    if status == "INCOMPLETE":
        phases = {s["phase"] for s in steps}
        if "FINDING" not in phases or "REMEDIATION" not in phases:
            errs.append("INCOMPLETE needs findings and remediation")
    return errs


def dumps(steps: list[dict]) -> str:
    return json.dumps(steps, ensure_ascii=False, separators=(",", ":"))
