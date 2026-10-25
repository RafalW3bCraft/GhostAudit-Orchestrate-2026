"""evaluation/usage_report.md - token usage and cost for the final full-dataset run."""
from __future__ import annotations

import json
import os
from collections import defaultdict

from . import llm


def write_usage_report(path: str, n_requests: int, cfg: dict, used_llm: bool):
    prices = cfg.get("prices_usd_per_mtok", {})  # {"model": {"input": x, "output": y}}
    per = defaultdict(lambda: {"calls": 0, "in": 0, "out": 0})
    for e in llm.LEDGER:
        m = per[e["model"]]
        m["calls"] += 1
        m["in"] += e["input_tokens"]
        m["out"] += e["output_tokens"]
    lines = ["# Token usage and cost report", "",
             "Final full-dataset run that produced `output.csv`.", "",
             f"- Requests processed: {n_requests}",
             f"- LLM enabled for this run: {'yes' if used_llm else 'no (deterministic pipeline only)'}", ""]
    if not per:
        lines += ["No model calls were made in this run.", "",
                  "| Provider | Model | Calls | Input tokens | Output tokens | Est. cost (USD) |",
                  "|---|---|---|---|---|---|", "| - | - | 0 | 0 | 0 | 0.00 |", "",
                  "Total tokens: 0. Average tokens per request: 0. Estimated cost: $0.00 total, $0.00 per request."]
    else:
        lines += ["| Provider | Model | Calls | Input tokens | Output tokens | Est. cost (USD) |", "|---|---|---|---|---|---|"]
        tc = ti = to = tcost = 0
        for model, m in per.items():
            pr = prices.get(model)
            cost = (m["in"] * pr["input"] + m["out"] * pr["output"]) / 1e6 if pr else None
            lines.append(f"| Anthropic | {model} | {m['calls']} | {m['in']} | {m['out']} | "
                         f"{'%.4f' % cost if cost is not None else 'price not configured'} |")
            tc += m["calls"]; ti += m["in"]; to += m["out"]; tcost += cost or 0
        n = max(n_requests, 1)
        lines += [f"| **Total** | | {tc} | {ti} | {to} | {'%.4f' % tcost} |", "",
                  f"- Total tokens: {ti + to}", f"- Average tokens per request: {(ti + to) / n:.1f}",
                  f"- Estimated cost: ${tcost:.4f} total, ${tcost / n:.6f} per request",
                  "- Prices come from `config.json` -> `prices_usd_per_mtok`; edit them to match your provider's price list."]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
