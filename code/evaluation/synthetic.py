"""Hand-built evaluation cases in the REAL dataset schema (headers/formats mirror
dataset/*.csv and dataset/evidence/*). Expected answers are hand-derived, NOT produced
by the planner, so they independently check the pipeline.

Cases:
  case_000  non-deletion request (data export)                       -> NOT_APPLICABLE
  case_001  profile still in a replica snapshot, search hit, active
            connector, restorable backup, PII support ticket,
            identifiable analytics profile                          -> INCOMPLETE (full plan)
  case_002  request via a HISTORICAL email; profile 404 in a service
            export, anonymized analytics, redacted support,
            disabled connector, blocked backup, audit record kept    -> COMPLETE (verify only)
  case_003  negated request ("do not delete")                        -> NOT_APPLICABLE
  case_004  account tombstone still holds email + name (bundle)      -> INCOMPLETE (redact)
  case_005  record visible only through an email hash in a SQL dump  -> INCOMPLETE (delete)
  case_006  evidence captured AFTER audit_at must be ignored         -> COMPLETE
"""
from __future__ import annotations

import csv
import hashlib
import json
import os


def h(e):
    return hashlib.sha256(e.encode()).hexdigest()


def _w(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


def S(op, sys_, res, ev=""):
    from ghostaudit.schema import OP_PHASE, OP_STATE
    return {"phase": OP_PHASE[op], "system_id": sys_, "resource_id": res, "operation": op,
            "state": OP_STATE[op], "evidence_id": ev}


def build(root: str) -> list[dict]:
    os.makedirs(os.path.join(root, "evidence"), exist_ok=True)
    emails = {"user_01": "ana@example.com", "user_02": "ben.new@example.com",
              "user_03": "cy@example.com", "user_04": "dee@example.com",
              "user_05": "eli@example.com", "user_06": "fay@example.com"}
    names = {"user_01": "Ana Rivera", "user_02": "Ben Carter", "user_03": "Cy Dunn",
             "user_04": "Dee Park", "user_05": "Eli Moss", "user_06": "Fay Cole"}
    _w(os.path.join(root, "user_identities.csv"),
       ["user_id", "name", "email", "phone", "email_hash", "updated_at"],
       [[u, names[u], e, f"+1 555 01{i}0 {i}{i}{i}{i}", h(e), "2026-01-01T00:00:00Z"]
        for i, (u, e) in enumerate(emails.items(), 1)])
    _w(os.path.join(root, "user_audit_log.csv"),
       ["audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"],
       [["audit_01", "user_02", "2026-01-10T00:00:00Z", "email",
         "ben.old@example.com", "ben.new@example.com"]])
    _w(os.path.join(root, "system_activity.csv"),
       ["activity_id", "event_time", "event_type", "source_system", "target_system",
        "resource_id", "reported_result", "details"],
       [["activity_01", "2026-02-02T09:00:00Z", "DELETE_RECORD", "deletion_worker",
         "account_service", "account_001", "SUCCESS",
         "Deletion worker reported the requested operation as completed. Target resource: account_001."],
        ["activity_02", "2026-02-02T09:05:00Z", "DELETE_RECORD", "deletion_worker",
         "account_service", "account_002", "SUCCESS",
         "Deletion worker reported the requested operation as completed. Target resource: account_002."]])
    _w(os.path.join(root, "deletion_rules.csv"),
       ["rule_id", "data_category", "condition", "required_action"],
       [["rule_01", "USER_PROFILE", "Always", "DELETE"],
        ["rule_03", "SEARCH_INDEX_ENTRY", "Always", "DELETE"],
        ["rule_05", "SUPPORT_MESSAGE", "Conversation contains shared context", "REDACT"],
        ["rule_07", "ANALYTICS_PROFILE", "Record is still attributable to a user", "ANONYMIZE"],
        ["rule_12", "SECURITY_AUDIT_LOG", "Record is within the supplied retention period", "RETAIN"],
        ["rule_14", "BACKUP_ARCHIVE", "Restore access can be blocked", "RETAIN"],
        ["rule_15", "ACCOUNT_TOMBSTONE", "Account is deleted", "REDACT"],
        ["rule_16", "DATA_FLOW", "Flow is active", "DISABLE"]])

    # --- evidence -------------------------------------------------------------
    # service_resource_export (freshest, 2026-02-09): state used by most cases
    jw = lambda name, obj: json.dump(obj, open(os.path.join(root, "evidence", name), "w"))
    jw("service_resource_export_20260209.json", {
        "exported_at": "2026-02-09T11:00:00Z", "region": "global",
        "source": "records_assurance_gateway",
        "service_exports": {
            "account_service": {"profile_lookups": [
                {"observed_at": "2026-02-09T10:00:00Z", "profile": None,
                 "resource_id": "account_002", "status_code": 404},
                {"observed_at": "2026-02-09T10:01:00Z",
                 "profile": {"customer_reference": "user_01", "email": "ana@example.com",
                             "email_hash": h("ana@example.com"), "full_name": "Ana Rivera",
                             "phone": "+1 555 0100 1111"},
                 "resource_id": "account_001", "status_code": 200}]},
            "analytics_platform": {"profiles": [
                {"audience_cohort": "general_shopper", "customer_reference": "user_02",
                 "email": None, "email_hash": None, "observed_at": "2026-02-09T10:02:00Z",
                 "phone": None, "resource_id": "analytics_202"},
                {"audience_cohort": "mobile_browser", "customer_reference": None,
                 "email": "ana@example.com", "email_hash": None,
                 "observed_at": "2026-02-09T10:03:00Z", "phone": None,
                 "resource_id": "analytics_101"}]},
            "backup_service": {"restore_entries": [
                {"archive_key": "archive/customer-data/backup_202.tar.zst",
                 "customer_email": None, "customer_reference": "user_02",
                 "observed_at": "2026-02-09T10:04:00Z", "resource_id": "backup_202",
                 "restore_allowed": False},
                {"archive_key": "archive/customer-data/backup_101.tar.zst",
                 "customer_email": "ana@example.com", "customer_reference": None,
                 "observed_at": "2026-02-09T10:05:00Z", "resource_id": "backup_101",
                 "restore_allowed": True}]},
            "integration_service": {"connectors": [
                {"connector_name": "analytics_identity_bridge", "customer_email": None,
                 "customer_reference": "user_02", "enabled": False,
                 "last_delivery_status": "stopped", "observed_at": "2026-02-09T10:06:00Z",
                 "resource_id": "data_flow_202"},
                {"connector_name": "customer_events_connector",
                 "customer_email": "ana@example.com", "customer_reference": None,
                 "enabled": True, "last_delivery_status": "delivered",
                 "observed_at": "2026-02-09T10:07:00Z", "resource_id": "data_flow_101"}]},
            "search_service": {"index_queries": [
                {"hits": {"documents": [{"customer_reference": None, "display_name": None,
                                         "email": "ana@example.com", "email_hash": None,
                                         "phone": None, "resource_id": "search_101"}],
                          "total": 1},
                 "observed_at": "2026-02-09T10:08:00Z", "query": "ana@example.com",
                 "resource_id": "search_101"}]},
            "security_service": {"audit_records": [
                {"event_code": "IDENTITY_CHANGE_RECORDED",
                 "observed_at": "2026-02-09T10:09:00Z", "resource_id": "audit_record_202",
                 "retention_until": "2034-09-30T23:59:59Z", "subject_reference": "user_02"}]},
            "support_platform": {"tickets": [
                {"customer_reference": "user_02", "message_excerpt": "[REDACTED]",
                 "observed_at": "2026-02-09T10:10:00Z", "requester_email": None,
                 "requester_name": None, "requester_phone": None,
                 "resource_id": "support_202"},
                {"customer_reference": None, "message_excerpt": "Customer asked about a delivery.",
                 "observed_at": "2026-02-09T10:11:00Z", "requester_email": "ana@example.com",
                 "requester_name": None, "requester_phone": None,
                 "resource_id": "support_101"}]}}})  # noqa: E501

    # SQL dump with a hash-only marketing-style contact for user_03
    with open(os.path.join(root, "evidence", "customer_data_inventory_20260206.sql"), "w") as fh:
        fh.write("BEGIN TRANSACTION;\n"
                 "CREATE TABLE customer_profiles (resource_id TEXT PRIMARY KEY, customer_reference TEXT, "
                 "full_name TEXT, email TEXT, phone TEXT, email_hash TEXT, account_status TEXT NOT NULL, "
                 "updated_at TEXT NOT NULL);\n"
                 f"INSERT INTO customer_profiles VALUES ('account_003', NULL, NULL, NULL, NULL, '{h('cy@example.com')}', "
                 "'DELETION_PENDING', '2026-02-06T08:00:00Z');\nCOMMIT;\n")
    # tombstone bundle for user_05 (still holds PII)
    jw("customer_data_snapshot_bundle_20260207.json", {
        "exported_at": "2026-02-07T12:00:00Z", "source": "records_assurance_service",
        "snapshots": [
            {"captured_at": "2026-02-07T12:00:00Z", "data_store": "identity_service",
             "collection": "deleted_customer_references",
             "records": [{"resource_id": "tombstone_505", "subject_reference": "user_05",
                          "name": "Eli Moss", "email": "eli@example.com", "phone": None,
                          "email_hash": None, "account_status": "DELETED"}]}]})
    # late evidence (after audit_at of case_006) that must be ignored
    jw("late.json", {"records": [{"resource_id": "search_999", "email": "fay@example.com",
                                  "customer_reference": "user_06"}]})
    _w(os.path.join(root, "evidence_files.csv"),
       ["file_id", "file_path", "origin", "captured_at"],
       [["evidence_01", "evidence/service_resource_export_20260209.json",
         "service_resource_export", "2026-02-09T11:00:00Z"],
        ["evidence_02", "evidence/customer_data_inventory_20260206.sql",
         "customer_data_inventory_capture", "2026-02-06T08:00:00Z"],
        ["evidence_03", "evidence/customer_data_snapshot_bundle_20260207.json",
         "records_assurance_snapshot_bundle", "2026-02-07T12:00:00Z"],
        ["evidence_99", "evidence/late.json", "search_index_service", "2026-03-01T00:00:00Z"]])

    reqs = [
        ["case_000", emails["user_03"], "2026-02-01T08:00:00Z", "NOT_STARTED", "",
         "2026-02-10T00:00:00Z", "Please export a copy of my data."],
        ["case_001", emails["user_01"], "2026-02-01T08:00:00Z", "COMPLETE", "2026-02-02T10:00:00Z",
         "2026-02-10T00:00:00Z", "Please delete my account and all my personal data."],
        ["case_002", "ben.old@example.com", "2026-02-01T08:00:00Z", "COMPLETE", "2026-02-02T10:00:00Z",
         "2026-02-10T00:00:00Z", "I want my account erased under GDPR."],
        ["case_003", emails["user_04"], "2026-02-01T08:00:00Z", "NOT_STARTED", "",
         "2026-02-10T00:00:00Z", "Please do not delete my account."],
        ["case_004", emails["user_05"], "2026-02-01T08:00:00Z", "COMPLETE", "2026-02-02T10:00:00Z",
         "2026-02-10T00:00:00Z", "Delete my data, I no longer use the service."],
        ["case_005", emails["user_03"], "2026-02-01T08:00:00Z", "COMPLETE", "2026-02-02T10:00:00Z",
         "2026-02-10T00:00:00Z", "Erase me please."],
        ["case_006", emails["user_06"], "2026-02-01T08:00:00Z", "COMPLETE", "2026-02-02T10:00:00Z",
         "2026-02-10T00:00:00Z", "Delete everything you hold about me."]]
    _w(os.path.join(root, "deletion_requests.csv"),
       ["case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at",
        "request_text"], reqs)

    ac, an, sp, ss, it, bk, sec, ids = ("account_service", "analytics_platform",
        "support_platform", "search_service", "integration_service", "backup_service",
        "security_service", "identity_service")
    c1 = ([S("REPORT_REMAINING_RECORD", ac, "account_001", "evidence_01"),
           S("REPORT_REMAINING_RECORD", ss, "search_101", "evidence_01"),
           S("REPORT_EXPOSED_PII", an, "analytics_101", "evidence_01"),
           S("REPORT_EXPOSED_PII", sp, "support_101", "evidence_01"),
           S("REPORT_ACTIVE_DATA_FLOW", it, "data_flow_101", "evidence_01"),
           S("REPORT_RESTORE_RISK", bk, "backup_101", "evidence_01")],
          [S("DISABLE_DATA_FLOW", it, "data_flow_101"),
           S("BLOCK_RESTORE", bk, "backup_101"),
           S("DELETE_RECORD", ac, "account_001"),
           S("DELETE_RECORD", ss, "search_101"),
           S("REDACT_RECORD", sp, "support_101"),
           S("ANONYMIZE_RECORD", an, "analytics_101")],
          [S("VERIFY_RECORD_ABSENT", ac, "account_001"),
           S("VERIFY_RECORD_ABSENT", ss, "search_101"),
           S("VERIFY_RECORD_REDACTED", sp, "support_101"),
           S("VERIFY_RECORD_ANONYMIZED", an, "analytics_101"),
           S("VERIFY_DATA_FLOW_DISABLED", it, "data_flow_101"),
           S("VERIFY_RESTORE_BLOCKED", bk, "backup_101")])
    c2 = [S("VERIFY_RECORD_ABSENT", ac, "account_002", "evidence_01"),
          S("VERIFY_RECORD_REDACTED", sp, "support_202", "evidence_01"),
          S("VERIFY_RECORD_ANONYMIZED", an, "analytics_202", "evidence_01"),
          S("VERIFY_DATA_FLOW_DISABLED", it, "data_flow_202", "evidence_01"),
          S("VERIFY_RESTORE_BLOCKED", bk, "backup_202", "evidence_01"),
          S("VERIFY_RECORD_PRESENT", sec, "audit_record_202", "evidence_01")]
    c4 = [S("REPORT_EXPOSED_PII", ids, "tombstone_505", "evidence_03"),
          S("REDACT_RECORD", ids, "tombstone_505"),
          S("VERIFY_RECORD_REDACTED", ids, "tombstone_505")]
    c5 = [S("REPORT_REMAINING_RECORD", ac, "account_003", "evidence_02"),
          S("DELETE_RECORD", ac, "account_003"),
          S("VERIFY_RECORD_ABSENT", ac, "account_003")]

    def num(steps):
        flat = []
        for part in steps:
            flat += part if isinstance(part, list) else [part]
        return json.dumps([{"step_no": i, **s} for i, s in enumerate(flat, 1)],
                          separators=(",", ":"))
    gold = [{"case_id": "case_000", "deletion_status": "NOT_APPLICABLE", "steps_json": "[]"},
            {"case_id": "case_001", "deletion_status": "INCOMPLETE", "steps_json": num(c1)},
            {"case_id": "case_002", "deletion_status": "COMPLETE", "steps_json": num(c2)},
            {"case_id": "case_003", "deletion_status": "NOT_APPLICABLE", "steps_json": "[]"},
            {"case_id": "case_004", "deletion_status": "INCOMPLETE", "steps_json": num(c4)},
            {"case_id": "case_005", "deletion_status": "INCOMPLETE", "steps_json": num(c5)},
            {"case_id": "case_006", "deletion_status": "COMPLETE", "steps_json": "[]"}]
    return gold
