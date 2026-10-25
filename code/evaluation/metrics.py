"""Scoring: status, step-level, field-level, sequence accuracy."""
from __future__ import annotations

import json
from collections import Counter

FIELDS = ("phase", "system_id", "resource_id", "operation", "state", "evidence_id")


def _steps(row):
    try:
        return json.loads(row.get("steps_json") or "[]")
    except ValueError:
        return []


def _lcs(a, b):
    if not a or not b:
        return 0
    prev = [0] * (len(b) + 1)
    for x in a:
        cur = [0]
        for j, y in enumerate(b, 1):
            cur.append(prev[j - 1] + 1 if x == y else max(prev[j], cur[-1]))
        prev = cur
    return prev[-1]


def score(pred_rows, gold_rows):
    pred = {r["case_id"]: r for r in pred_rows}
    gold = {r["case_id"]: r for r in gold_rows}
    ids = sorted(gold)
    n = len(ids)
    status_ok = exact_ok = 0
    tp = fp = fn = 0
    ftp = fn_total = 0
    field_hits = Counter()
    lcs_sum = 0.0
    fails = []
    for cid in ids:
        g, p = gold[cid], pred.get(cid, {"deletion_status": "", "steps_json": "[]"})
        gs, ps = _steps(g), _steps(p)
        s_ok = g["deletion_status"] == p["deletion_status"]
        status_ok += s_ok
        gk = Counter(tuple(s.get(f, "") for f in FIELDS) for s in gs)
        pk = Counter(tuple(s.get(f, "") for f in FIELDS) for s in ps)
        inter = sum((gk & pk).values())
        tp += inter; fp += sum(pk.values()) - inter; fn += sum(gk.values()) - inter
        gi = {(s["operation"], s["system_id"], s["resource_id"]): s for s in gs}
        pi = {(s["operation"], s["system_id"], s["resource_id"]): s for s in ps}
        for k, s in gi.items():
            fn_total += 1
            if k in pi:
                ftp += 1
                for f in FIELDS:
                    field_hits[f] += pi[k].get(f, "") == s.get(f, "")
        gseq = [tuple(s.get(f, "") for f in FIELDS) for s in gs]
        pseq = [tuple(s.get(f, "") for f in FIELDS) for s in ps]
        l = _lcs(gseq, pseq)
        lcs_sum += 1.0 if not gseq and not pseq else (2 * l / (len(gseq) + len(pseq)))
        e_ok = s_ok and gseq == pseq
        exact_ok += e_ok
        if not e_ok:
            fails.append({"case_id": cid, "gold_status": g["deletion_status"], "pred_status": p["deletion_status"],
                          "missing": [list(k) for k in (gk - pk)][:6], "extra": [list(k) for k in (pk - gk)][:6]})
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 1.0
    return {
        "cases": n, "status_accuracy": status_ok / n if n else 0,
        "step_precision": prec, "step_recall": rec,
        "step_f1": 2 * prec * rec / (prec + rec) if prec + rec else 0,
        "field_accuracy": {f: (field_hits[f] / ftp if ftp else 0) for f in FIELDS},
        "matched_step_keys": f"{ftp}/{fn_total}",
        "sequence_accuracy_exact": exact_ok / n if n else 0,
        "sequence_similarity_lcs": lcs_sum / n if n else 0,
        "failures": fails,
    }
