"""Did the person actually request deletion? Multilingual, negation-aware, LLM only if ambiguous."""
from __future__ import annotations

import re

from . import llm

DELETE_RE = re.compile(
    r"(delet\w*|erase\w*|eras\w*|remov\w*|wipe\w*|purge\w*|forget me|right to be forgotten|"
    r"right to erasure|erasure|gdpr|ccpa|close\w* (?:my|the|this) account|closure of (?:my )?account|"
    r"eliminar\w*|borrar\w*|suprimir\w*|supprim\w+|effac\w+|suppression|l[öo]sch\w*|entfern\w*|"
    r"excluir\w*|apag\w+|cancell?are|elimin\w+|verwijder\w*|usu[nń]\w*|удал\w*|削除|删除|刪除|삭제)",
    re.I)
_VERBS = (r"(?:delet\w*|erase\w*|remov\w*|wipe\w*|purge\w*|eliminar\w*|borrar\w*|supprim\w*|effac\w*|"
          r"l[öo]sch\w*|excluir\w*|apag\w*|cancell?are|close)")
_NEG = (r"(?:\bnot\b|n't|\bnever\b|\bno\b|\bne\b|\bnicht\b|\bn[aã]o\b|\bnon\b|\bkeine?\b|\bpas\b|\bsin\b)")
NEGATION_RE = re.compile(_NEG + r"\s+(?:[\w']+\s+){0,3}?" + _VERBS, re.I)
RETRACT_RE = re.compile(r"(cancel|withdraw|rescind|ignore|disregard|retract)[^.!?\n]{0,30}(deletion|delete|erasure|request)", re.I)
OTHER_RE = re.compile(r"\b(export|download|copy of my data|access request|update my|change my|reset|"
                      r"password|subscription|refund|invoice|status of|unsubscribe)\b", re.I)


def classify(text: str) -> tuple[bool, float]:
    """Return (deletion_requested, confidence)."""
    t = text or ""
    pos = bool(DELETE_RE.search(t))
    # "switch off / disable any integration that could copy data back" is a deletion-side ask
    if not pos and re.search(r"(switch off|disable|stop).{0,40}(integration|sync|connector|copy)", t, re.I) and \
            re.search(r"remov\w*|delet\w*|account", t, re.I):
        pos = True
    # "check/confirm whether the deletion already happened" authorises the audit
    if not pos and re.search(r"(check|inspect|confirm|verify|whether).{0,80}"
                             r"(deleted|deletion|removed|gone|erased|identify me)", t, re.I):
        pos = True
    neg = t.isascii() and (bool(NEGATION_RE.search(t)) or bool(RETRACT_RE.search(t)))
    if not pos:
        return False, 0.9 if (OTHER_RE.search(t) or t.isascii()) else 0.4
    if neg:
        return False, 0.6
    if OTHER_RE.search(t) and not re.search(r"\b(delete|erase|remove)\b.{0,40}\b(account|data|information|profile)\b", t, re.I):
        return True, 0.6
    return True, 0.95


def deletion_requested(text: str, use_llm: bool = False) -> bool:
    label, conf = classify(text)
    if use_llm and conf < 0.7:
        out = llm.ask_json(
            "You classify customer messages. Answer with JSON {\"deletion_requested\": true|false}. "
            "True only if the person is actually asking for their personal data/account to be deleted now. "
            "False if they retract, refuse, or ask for something else (export, update, access).",
            text, "intent")
        if out and isinstance(out.get("deletion_requested"), bool):
            return out["deletion_requested"]
    return label
