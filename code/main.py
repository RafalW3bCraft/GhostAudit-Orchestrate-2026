#!/usr/bin/env python3
"""Ghost Data Still Exists - deletion audit agent.

Usage (from repo root):
  python code/main.py                         # dataset/deletion_requests.csv -> output.csv
  python code/main.py --probe                 # print real column headers / rule rows / evidence types
  python code/main.py --eval                  # score on dataset/sample_* and write evaluation report
"""
from __future__ import annotations

import argparse
import csv
import os
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from ghostaudit.agent import Agent  # noqa: E402
from ghostaudit.common import load_config, read_csv  # noqa: E402
from ghostaudit.reports import write_usage_report  # noqa: E402


def probe(dataset):
    for name in ("deletion_requests", "sample_deletion_requests", "user_identities", "user_audit_log",
                 "system_activity", "deletion_rules", "evidence_files", "sample_output"):
        rows = read_csv(os.path.join(dataset, name + ".csv"))
        print(f"\n== {name}.csv  rows={len(rows)}")
        if rows:
            print("columns:", list(rows[0].keys()))
            for r in rows[: (15 if name == 'deletion_rules' else 2)]:
                print("  ", {k: (v[:90] if isinstance(v, str) else v) for k, v in r.items()})
    ev = os.path.join(dataset, "evidence")
    if os.path.isdir(ev):
        c = Counter(os.path.splitext(f)[1].lower() for _, _, fs in os.walk(ev) for f in fs)
        print("\n== evidence/ file types:", dict(c))


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["case_id", "deletion_status", "steps_json"])
        w.writeheader()
        w.writerows(rows)


def main():
    root = os.path.dirname(HERE)
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=os.path.join(root, "dataset"))
    ap.add_argument("--requests", default=None)
    ap.add_argument("--output", default=os.path.join(root, "output.csv"))
    ap.add_argument("--config", default=os.path.join(HERE, "config.json"))
    ap.add_argument("--use-llm", action="store_true", help="LLM for ambiguous intent / image OCR fallback")
    ap.add_argument("--probe", action="store_true")
    ap.add_argument("--eval", action="store_true")
    a = ap.parse_args()
    if a.probe:
        return probe(a.dataset)
    if a.eval:
        from evaluation.run_eval import run_all
        return run_all(a.dataset, a.config, a.use_llm, os.path.join(HERE, "evaluation"))
    req_path = a.requests or os.path.join(a.dataset, "deletion_requests.csv")
    requests = read_csv(req_path)
    agent = Agent(a.dataset, a.config, a.use_llm)
    rows = agent.run(requests)
    write_csv(a.output, rows)
    write_usage_report(os.path.join(HERE, "evaluation", "usage_report.md"), len(rows), load_config(a.config), a.use_llm)
    st = Counter(r["deletion_status"] for r in rows)
    print(f"wrote {len(rows)} rows to {a.output}: {dict(st)}")
    print(f"evidence files parsed: {agent.ev.file_count}; warnings: {len(agent.warnings)}; validation errors: {len(agent.errors)}")
    log = os.path.join(HERE, "evaluation", "run_log.txt")
    os.makedirs(os.path.dirname(log), exist_ok=True)
    with open(log, "w", encoding="utf-8") as fh:
        fh.write("\n".join(["# warnings"] + agent.warnings + ["# errors"] + agent.errors))


if __name__ == "__main__":
    main()
