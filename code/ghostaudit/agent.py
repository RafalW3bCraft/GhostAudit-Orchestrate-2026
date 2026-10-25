"""End-to-end agent: request -> intent -> identity -> evidence state -> plan -> row."""
from __future__ import annotations

import os
import traceback

from .common import Cols, load_config, parse_ts, read_csv
from .evidence import EvidenceIndex
from .identity import Identity, IdentityIndex
from .intent import deletion_requested
from .planner import plan
from .policy import Policy
from .schema import dumps, validate
from .state import Activity, build_items, ResourceWorld


class Agent:
    def __init__(self, dataset_dir: str, config_path: str | None = None, use_llm: bool = False):
        self.cfg = load_config(config_path)
        ov = self.cfg.get("columns", {})
        self.dir = dataset_dir
        self.use_llm = use_llm
        p = lambda n: os.path.join(dataset_dir, n)
        self.ids = IdentityIndex(read_csv(p("user_identities.csv")), read_csv(p("user_audit_log.csv")), ov)
        self.policy = Policy(read_csv(p("deletion_rules.csv")), ov)
        self.activity = Activity(read_csv(p("system_activity.csv")), ov)
        self.ev = EvidenceIndex(dataset_dir, ov)
        self.warnings: list[str] = list(self.ev.warnings)
        self.errors: list[str] = []
        self.traces: dict[str, dict] = {}

    def run_case(self, row: dict) -> tuple[str, list[dict]]:
        rc = Cols([row], "requests")
        case_id = rc.get(row, "case_id")
        try:
            if not deletion_requested(rc.get(row, "request_text"), self.use_llm):
                self.traces[case_id] = {"intent": False}
                return "NOT_APPLICABLE", []
            email = rc.get(row, "email")
            ident = self.ids.resolve(email) or Identity("", emails={email.strip().lower()})
            if not ident.user_id:
                ident.finalize()
                self.warnings.append(f"{case_id}: {email} not resolvable to a user_id")
            audit_at = parse_ts(rc.get(row, "audit_at")) or parse_ts("2999-01-01")
            warn: list[str] = []
            items = build_items(ident, self.ev.world, audit_at, warn)
            # The primary profile resource id is observable only where evidence pairs it
            # with one of the user's identifiers (lookup traces, profile rows). Where it
            # is not observable at all, fall back to naming it after the deletion
            # workflow's own DELETE_RECORD activity (a claim used solely to NAME the
            # resource; its reported result is never trusted for state).
            if not any(i.system_id == "account_service" for i in items):
                rid = self.activity.account_resource(ident, audit_at,
                                                     rc.get(row, "requested_at"),
                                                     rc.get(row, "reported_at"))
                if rid:
                    from .state import Item, ST_ABSENT
                    ev_id, st = self.ev.absence_evidence("account_service", rid, audit_at)
                    items.append(Item("record", "account_service", rid, "USER_PROFILE",
                                      st, ev_id, set(), True, verified=bool(ev_id)))
            status, steps = plan(items, self.policy, self.activity.deleted_resources)
            errs = validate(status, steps)
            if errs:
                self.errors.append(f"{case_id}: {errs}")
            self.warnings += [f"{case_id}: {w}" for w in warn]
            self.traces[case_id] = {"intent": True, "user_id": ident.user_id,
                                    "items": [i.__dict__ | {"pii": sorted(i.pii)} for i in items]}
            return status, steps
        except Exception:
            self.errors.append(f"{case_id}: crashed\n{traceback.format_exc()}")
            return "INCOMPLETE", []

    def run(self, requests: list[dict]) -> list[dict]:
        out = []
        for row in requests:
            cid = Cols([row], "requests").get(row, "case_id")
            status, steps = self.run_case(row)
            out.append({"case_id": cid, "deletion_status": status, "steps_json": dumps(steps)})
        out.sort(key=lambda r: r["case_id"])
        return out
