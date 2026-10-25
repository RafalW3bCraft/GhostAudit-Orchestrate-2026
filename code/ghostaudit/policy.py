"""deletion_rules.csv -> treatment + allowed identifiers per data category."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .common import Cols

KIND_WORDS = {"email": "email", "e-mail": "email", "phone": "phone",
              "hash": "email_hash", "name": "name", "user_id": "user_id",
              "user id": "user_id", "stable": "user_id", "reference": "user_id"}


def norm_treatment(*texts: str) -> str:
    t = " ".join(texts).lower()
    for pat, val in (("block", "BLOCK"), ("disable", "DISABLE"), ("stop", "DISABLE"),
                     ("anonym", "ANONYMIZE"), ("redact", "REDACT"), ("mask", "REDACT"),
                     ("tombstone", "REDACT"), ("retain", "RETAIN"), ("keep", "RETAIN"),
                     ("preserve", "RETAIN"), ("hold", "RETAIN"), ("delete", "DELETE"),
                     ("erase", "DELETE"), ("remove", "DELETE"), ("purge", "DELETE")):
        if pat in t:
            return val
    return "DELETE"


@dataclass
class Rule:
    rule_id: str
    category: str
    treatment: str
    allowed: set = field(default_factory=set)
    condition: str = ""


class Policy:
    def __init__(self, rows, overrides=None):
        c = Cols(rows, "rules", overrides)
        self.by_cat: dict[str, Rule] = {}
        for r in rows:
            treat_raw = c.get(r, "treatment")
            desc = c.get(r, "description")
            allowed_txt = " ".join([c.get(r, "allowed"), desc]).lower()
            allowed = {v for k, v in KIND_WORDS.items() if k in allowed_txt}
            treatment = norm_treatment(treat_raw) if treat_raw else norm_treatment(desc)
            if treatment == "RETAIN" and not allowed:
                allowed = {"user_id"}
            rule = Rule(c.get(r, "rule_id"), c.get(r, "category").upper(), treatment,
                        allowed, desc)
            self.by_cat[rule.category] = rule
        # A subject-owned attachment (support_001-style ids, documents under
        # evidence/documents, object_storage) is a SUPPORT_ATTACHMENT: delete it.
        if "SUPPORT_ATTACHMENT" not in self.by_cat and "SUPPORT_MESSAGE" in self.by_cat:
            pass  # keep whatever the rules say verbatim

    def match(self, category: str) -> Rule | None:
        return self.by_cat.get((category or "").upper())
