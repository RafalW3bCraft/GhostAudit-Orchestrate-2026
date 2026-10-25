import csv, json, os, re, shutil, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ghostaudit.agent import Agent
from ghostaudit.common import read_csv
from ghostaudit.schema import finalize, make_step, validate
from evaluation.synthetic import build


def run(d, **kw):
    ag = Agent(d, None, False)
    rows = ag.run(read_csv(os.path.join(d, "deletion_requests.csv")))
    return ag, {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in rows}


class T(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        build(self.d)

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_all_outputs_validate(self):
        ag, res = run(self.d)
        self.assertEqual(ag.errors, [])
        for st, steps in res.values():
            self.assertEqual(validate(st, steps), [])

    def test_future_evidence_ignored(self):
        # evidence_99 (captured 2026-03-01, after audit_at 2026-02-10) must never be used
        _, res = run(self.d)
        self.assertEqual(res["case_006"][0], "COMPLETE")
        for s in res["case_006"][1]:
            self.assertNotEqual(s["resource_id"], "search_999")

    def test_intent_gate(self):
        _, res = run(self.d)
        self.assertEqual(res["case_000"][0], "NOT_APPLICABLE")   # export request
        self.assertEqual(res["case_000"][1], [])
        self.assertEqual(res["case_003"][0], "NOT_APPLICABLE")   # "do not delete"
        self.assertEqual(res["case_003"][1], [])

    def test_historical_email_resolves_and_complete(self):
        _, res = run(self.d)
        self.assertEqual(res["case_002"][0], "COMPLETE")
        keys = {(s["operation"], s["system_id"], s["resource_id"], s["evidence_id"])
                for s in res["case_002"][1]}
        self.assertIn(("VERIFY_RECORD_ABSENT", "account_service", "account_002", "evidence_01"), keys)
        self.assertIn(("VERIFY_RECORD_PRESENT", "security_service", "audit_record_202", "evidence_01"), keys)
        self.assertIn(("VERIFY_RECORD_ANONYMIZED", "analytics_platform", "analytics_202", "evidence_01"), keys)
        self.assertIn(("VERIFY_RECORD_REDACTED", "support_platform", "support_202", "evidence_01"), keys)
        self.assertIn(("VERIFY_DATA_FLOW_DISABLED", "integration_service", "data_flow_202", "evidence_01"), keys)
        self.assertIn(("VERIFY_RESTORE_BLOCKED", "backup_service", "backup_202", "evidence_01"), keys)

    def test_incomplete_full_plan(self):
        _, res = run(self.d)
        self.assertEqual(res["case_001"][0], "INCOMPLETE")
        keys = {(s["operation"], s["system_id"], s["resource_id"]) for s in res["case_001"][1]}
        self.assertIn(("REPORT_REMAINING_RECORD", "account_service", "account_001"), keys)
        self.assertIn(("REPORT_REMAINING_RECORD", "search_service", "search_101"), keys)
        self.assertIn(("REPORT_EXPOSED_PII", "analytics_platform", "analytics_101"), keys)
        self.assertIn(("REPORT_EXPOSED_PII", "support_platform", "support_101"), keys)
        self.assertIn(("REPORT_ACTIVE_DATA_FLOW", "integration_service", "data_flow_101"), keys)
        self.assertIn(("REPORT_RESTORE_RISK", "backup_service", "backup_101"), keys)
        self.assertIn(("DISABLE_DATA_FLOW", "integration_service", "data_flow_101"), keys)
        self.assertIn(("BLOCK_RESTORE", "backup_service", "backup_101"), keys)
        # remediation / verification carry empty evidence ids
        for s in res["case_001"][1]:
            if s["phase"] != "FINDING":
                self.assertEqual(s["evidence_id"], "")

    def test_disable_flow_precedes_deletes(self):
        _, res = run(self.d)
        ops = [s["operation"] for s in res["case_001"][1]]
        self.assertLess(ops.index("DISABLE_DATA_FLOW"), ops.index("DELETE_RECORD"))

    def test_sql_snapshot_and_email_hash(self):
        _, res = run(self.d)
        ops = [(s["operation"], s["system_id"], s["resource_id"]) for s in res["case_005"][1]]
        self.assertIn(("REPORT_REMAINING_RECORD", "account_service", "account_003"), ops)

    def test_tombstone_with_pii(self):
        _, res = run(self.d)
        self.assertEqual(res["case_004"][0], "INCOMPLETE")
        ops = [(s["operation"], s["system_id"], s["resource_id"]) for s in res["case_004"][1]]
        self.assertIn(("REPORT_EXPOSED_PII", "identity_service", "tombstone_505"), ops)
        self.assertIn(("REDACT_RECORD", "identity_service", "tombstone_505"), ops)
        self.assertIn(("VERIFY_RECORD_REDACTED", "identity_service", "tombstone_505"), ops)

    def test_perturbation_user_ids_and_row_order(self):
        """No hidden dependence on specific IDs: renaming user ids / reordering rows keeps answers equivalent."""
        _, base = run(self.d)
        d2 = tempfile.mkdtemp()
        try:
            for root, _, files in os.walk(self.d):
                for f in files:
                    src = os.path.join(root, f)
                    dst = os.path.join(d2, os.path.relpath(src, self.d))
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    txt = open(src, encoding="utf-8").read()
                    txt = re.sub(r"\buser_0(\d)\b", r"user_Z\1", txt)
                    open(dst, "w", encoding="utf-8").write(txt)
            rows = read_csv(os.path.join(d2, "deletion_requests.csv"))[::-1]
            with open(os.path.join(d2, "deletion_requests.csv"), "w", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
            _, pert = run(d2)
            self.assertEqual(base, pert)
        finally:
            shutil.rmtree(d2)

    def test_ordering_rules(self):
        s = finalize([make_step("VERIFY_RESTORE_BLOCKED", "b", "2"), make_step("DELETE_RECORD", "z", "1"),
                      make_step("DELETE_RECORD", "a", "9"), make_step("REPORT_RESTORE_RISK", "b", "2", "X"),
                      make_step("DISABLE_DATA_FLOW", "q", "1"), make_step("REPORT_REMAINING_RECORD", "a", "1", "E")])
        self.assertEqual([x["operation"] for x in s], ["REPORT_REMAINING_RECORD", "REPORT_RESTORE_RISK", "DISABLE_DATA_FLOW",
                                                       "DELETE_RECORD", "DELETE_RECORD", "VERIFY_RESTORE_BLOCKED"])
        self.assertEqual([x["system_id"] for x in s if x["operation"] == "DELETE_RECORD"], ["a", "z"])
        self.assertEqual([x["step_no"] for x in s], [1, 2, 3, 4, 5, 6])


if __name__ == "__main__":
    unittest.main(verbosity=2)
