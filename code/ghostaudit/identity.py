"""Identity resolution: current + historical emails, phones, hashes -> one user."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from .common import Cols, parse_ts

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
HASH_RE = re.compile(r"\b(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})\b")
PHONE_RE = re.compile(r"\+?\d[\d\s().\-]{5,}\d")
WORD_RE = re.compile(r"[A-Za-z0-9_\-]+")
DIRECT = {"email", "email_hash", "phone", "name"}


def norm_email(v: str) -> str:
    return v.strip().lower()


def phone_keys(v: str) -> set[str]:
    d = re.sub(r"\D", "", v or "")
    if len(d) < 7:
        return set()
    return {d, d[-10:]} if len(d) > 10 else {d}


def classify_value(v: str) -> str | None:
    v = (v or "").strip()
    if not v:
        return None
    if EMAIL_RE.fullmatch(v):
        return "email"
    if HASH_RE.fullmatch(v):
        return "email_hash"
    if len(re.sub(r"\D", "", v)) >= 7 and re.fullmatch(r"[+\d\s().\-]+", v):
        return "phone"
    return None


@dataclass
class Sig:
    emails: set
    hashes: set
    phones: set
    words: set
    lower: str


def signature(text: str) -> Sig:
    text = text or ""
    phones = set()
    for m in PHONE_RE.finditer(text):
        phones |= phone_keys(m.group(0))
    return Sig({e.lower() for e in EMAIL_RE.findall(text)},
               {h.lower() for h in HASH_RE.findall(text)}, phones,
               {w.lower() for w in WORD_RE.findall(text)}, text.lower())


@dataclass
class Identity:
    user_id: str
    emails: set = field(default_factory=set)
    phones: set = field(default_factory=set)
    hashes: set = field(default_factory=set)
    names: set = field(default_factory=set)
    audit_ids: list = field(default_factory=list)

    def finalize(self):
        for e in list(self.emails):
            b = e.encode()
            self.hashes |= {hashlib.sha256(b).hexdigest(), hashlib.sha1(b).hexdigest(),
                            hashlib.md5(b).hexdigest()}

    def lookup_tokens(self) -> set[str]:
        return ({self.user_id.lower()} | self.emails | self.hashes | self.phones)

    def match(self, sig: Sig) -> set[str]:
        k = set()
        if self.emails & sig.emails:
            k.add("email")
        if self.hashes & sig.hashes:
            k.add("email_hash")
        if self.phones & sig.phones:
            k.add("phone")
        if self.user_id and self.user_id.lower() in sig.words:
            k.add("user_id")
        if any(len(n) >= 5 and n in sig.lower for n in self.names):
            k.add("name")
        return k


class IdentityIndex:
    def __init__(self, identity_rows, audit_rows, overrides=None):
        ic, ac = Cols(identity_rows, "identities", overrides), Cols(audit_rows, "audit", overrides)
        self.users: dict[str, Identity] = {}
        self.token_user: dict[str, str] = {}
        for r in identity_rows:
            uid = ic.get(r, "user_id")
            if not uid:
                continue
            u = self.users.setdefault(uid, Identity(uid))
            if ic.get(r, "email"):
                u.emails.add(norm_email(ic.get(r, "email")))
            u.phones |= phone_keys(ic.get(r, "phone"))
            if ic.get(r, "email_hash"):
                u.hashes.add(ic.get(r, "email_hash").lower())
            if ic.get(r, "name"):
                u.names.add(ic.get(r, "name").lower())
        self._reindex()
        rows = sorted(audit_rows, key=lambda r: parse_ts(ac.get(r, "ts")) or parse_ts("1970-01-01"))
        for _ in range(2):  # second pass lets rows without user_id link through earlier changes
            for r in rows:
                vals = [ac.get(r, "old"), ac.get(r, "new")]
                uid = ac.get(r, "user_id")
                if not uid or uid not in self.users:
                    uid = next((self.token_user.get(self._key(v)) for v in vals
                                if self.token_user.get(self._key(v))), "")
                if not uid or uid not in self.users:
                    continue
                u = self.users[uid]
                for v in vals:
                    kind = classify_value(v)
                    if kind == "email":
                        u.emails.add(norm_email(v))
                    elif kind == "email_hash":
                        u.hashes.add(v.strip().lower())
                    elif kind == "phone":
                        u.phones |= phone_keys(v)
                    elif "name" in ac.get(r, "field").lower() and v:
                        u.names.add(v.strip().lower())
                if ac.get(r, "audit_id"):
                    u.audit_ids.append(ac.get(r, "audit_id"))
            self._reindex()

    @staticmethod
    def _key(v: str) -> str:
        v = (v or "").strip().lower()
        d = re.sub(r"\D", "", v)
        return v if "@" in v or not d or len(d) < 7 else d[-10:]

    def _reindex(self):
        self.token_user = {}
        for uid, u in self.users.items():
            u.finalize()
            for e in u.emails | u.hashes:
                self.token_user[e] = uid
            for p in u.phones:
                self.token_user[p[-10:]] = uid
            self.token_user[uid.lower()] = uid

    def resolve(self, email: str) -> Identity | None:
        uid = self.token_user.get(self._key(email))
        return self.users.get(uid) if uid else None
