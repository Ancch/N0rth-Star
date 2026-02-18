# backend/app/enricher.py
from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional
import re

# Basic technique: add enrichment tags + risk hints from text
# This is "context augmentation" for scoring and reporting.

TAG_RULES = [
    ("credential_leak", [r"\bpassword\b", r"\bpasswd\b", r"\bcreds?\b", r"\bcredential\b"]),
    ("api_key_exposure", [r"\bapi[_ -]?key\b", r"\bakia[0-9a-z]{16}\b"]),  # aws-ish
    ("token_exposure", [r"\bbearer\b", r"\bauthorization:\b", r"\btoken\b", r"\bjwt\b"]),
    ("private_key_exposure", [r"-----begin (rsa |ec |openssh )?private key-----"]),
    ("ddos", [r"\bddos\b", r"\bbotnet\b", r"\bflood\b"]),
    ("ransomware", [r"\bransomware\b", r"\bencrypt(ed|ion)?\b"]),
    ("sqli", [r"\bsql injection\b", r"\bunion select\b", r"(\bor\b)\s+1=1", r"--\s*$"]),
    ("xss", [r"\bxss\b", r"<script", r"onerror\s*="]),
    ("exploit", [r"\bexploit\b", r"\b0day\b", r"\bzero day\b", r"\bpoc\b"]),
    ("cve_mentioned", [r"\bcve-\d{4}-\d{4,7}\b"]),
]

KEYWORD_DENSITY = [
    "ddos", "ransomware", "exploit", "breach", "leak", "dump",
    "access", "creds", "credential", "password", "token", "key",
    "botnet", "selling", "for sale", "pwn", "owned", "cve",
    "0day", "zero day", "vulnerability", "attack"
]

def _lower(text: str) -> str:
    return (text or "").lower()

def keyword_hits(text: str) -> int:
    t = _lower(text)
    return sum(1 for k in KEYWORD_DENSITY if k in t)

def extract_tags(text: str) -> List[str]:
    t = _lower(text)
    tags = []
    for name, patterns in TAG_RULES:
        for p in patterns:
            if re.search(p, t, flags=re.IGNORECASE | re.MULTILINE):
                tags.append(name)
                break
    # de-dup while preserving order
    seen = set()
    out = []
    for x in tags:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def enrichment_summary(text: str) -> Dict[str, Any]:
    tags = extract_tags(text)
    hits = keyword_hits(text)
    # A simple “signal” scalar that scoring can use
    # (kept small so it’s a bonus, not dominating)
    signal_bonus = min(12.0, 2.0 * hits)
    return {
        "tags": tags,
        "attack_keyword_hits": hits,
        "signal_bonus": signal_bonus,
    }
