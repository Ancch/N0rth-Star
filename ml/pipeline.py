from __future__ import annotations

from dataclasses import asdict
from typing import Dict, Any, Optional

from ml.infer import NorthStarModels
from ml.detectors import leak_detector, entity_extractor
from ml.ioc_extractor import extract_iocs
from ml.cve_enricher import enrich_cves

SEVERITY_WEIGHTS = {
    "PRIVATE_KEY_BLOCK": 45,
    "CONNECTION_STRING": 30,
    "AWS_ACCESS_KEY_ID": 26,
    "GITHUB_TOKEN": 26,
    "JWT": 20,
    "AUTH_HEADER": 20,
    "PASSWORD_ASSIGNMENT": 16,
}

SECTOR_IMPACT = {
    "power_grid": 22,
    "telecom": 20,
    "banking": 20,
    "upi": 20,
    "airport": 16,
    "ports": 16,
    "railways": 15,
    "oil": 15,
    "other": 8,
}

INTENT_BOOST = {
    "planning": 14,
    "claim": 12,
    "leak": 14,
    "discussion": 6,
    "irrelevant": 0,
}

ATTACK_KEYWORDS = [
    "ddos", "ransomware", "exploit", "breach", "leak", "dump",
    "access", "creds", "credential", "password", "token", "key",
    "botnet", "sell", "selling", "for sale", "pwn", "owned",
    "cve", "0day", "zero day", "vulnerability", "attack"
]

SECTOR_HINTS = {
    "banking": ["bank", "banking", "swift", "atm"],
    "upi": ["upi", "npci", "payment gateway", "upi gateway"],
    "railways": ["rail", "railways", "irctc", "train"],
    "power_grid": ["power grid", "grid", "substation", "scada", "electric"],
    "telecom": ["telecom", "telco", "sim swap", "tower", "5g", "lte"],
    "airport": ["airport", "aviation", "airline"],
    "ports": ["port", "ports", "harbor", "harbour", "container terminal"],
    "oil": ["oil", "refinery", "pipeline", "gas plant", "petroleum"]
}

def clamp(x: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, x))

def keyword_hits(text: str, keywords: list[str]) -> int:
    t = (text or "").lower()
    return sum(1 for k in keywords if k in t)

def sector_override(text: str) -> tuple[Optional[str], int]:
    t = (text or "").lower()
    best = None
    best_hits = 0
    for sector, hints in SECTOR_HINTS.items():
        hits = sum(1 for h in hints if h in t)
        if hits > best_hits:
            best_hits = hits
            best = sector
    return (best, best_hits) if best_hits > 0 else (None, 0)

def score_threat(
    *,
    intent_label: str,
    intent_conf: float,
    sector_label: str,
    sector_conf: float,
    findings: list,
    vuln_risk: Optional[Dict[str, Any]] = None,
    security_like: bool = False,
    attack_kw_hits: int = 0
) -> Dict[str, Any]:
    reasons = []
    score = 0.0

    if findings:
        top = max(findings, key=lambda f: f.confidence)
        w = SEVERITY_WEIGHTS.get(top.type, 12)
        score += w
        reasons.append(f"Leak signal: {top.type} (+{w})")

        cred = 25.0 * float(top.confidence)
        score += cred
        reasons.append(f"Evidence confidence (+{cred:.1f})")

    ib = INTENT_BOOST.get(intent_label, 0)
    intent_part = ib * float(intent_conf)
    score += intent_part
    reasons.append(f"Intent: {intent_label} (+{intent_part:.1f})")

    sw = SECTOR_IMPACT.get(sector_label, 8)
    sector_part = sw * float(sector_conf)
    score += sector_part
    reasons.append(f"Sector impact: {sector_label} (+{sector_part:.1f})")

    if vuln_risk is not None:
        vr = float(vuln_risk.get("score", 0.0))
        vuln_part = min(30.0, (vr / 100.0) * 30.0)
        score += vuln_part
        reasons.append(f"Vulnerability risk (+{vuln_part:.1f})")

    if security_like:
        score += 6.0
        reasons.append("Security keywords present (+6)")

    if attack_kw_hits >= 2:
        bonus = min(12.0, 4.0 * attack_kw_hits)
        score += bonus
        reasons.append(f"Attack keyword density (+{bonus:.1f})")

    return {"score": clamp(score), "reasons": reasons}

def build_alert(
    text: str,
    post_meta: Optional[Dict[str, Any]] = None,
    vuln_features: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    post_meta = post_meta or {}
    text = text or ""

    models = NorthStarModels()

    pred = models.predict_all(text, vuln_features=vuln_features)
    intent = pred["intent"]
    sector_obj = pred["sectors"][0]

    sector_label = sector_obj["label"]
    sector_conf = float(sector_obj["confidence"])

    findings = leak_detector(text)
    entities = entity_extractor(text)

    attack_hits = keyword_hits(text, ATTACK_KEYWORDS)
    security_like = attack_hits > 0

    # Strong sector override
    ovr, hits = sector_override(text)
    if ovr and hits >= 1 and ovr != sector_label:
        sector_label = ovr
        sector_conf = max(sector_conf, 0.75)

    if findings:
        category = "leak"
    elif vuln_features is not None:
        category = "vulnerability"
    else:
        if (not security_like) and float(intent["confidence"]) < 0.45:
            category = "noise"
        else:
            category = "attack_chatter" if intent["label"] in ("planning", "claim") else "discussion"

    if intent["label"] == "irrelevant" and float(intent["confidence"]) >= 0.55 and not findings:
        category = "noise"

    vuln_risk = pred.get("vuln_risk") if vuln_features is not None else None

    scored = score_threat(
        intent_label=intent["label"],
        intent_conf=float(intent["confidence"]),
        sector_label=sector_label,
        sector_conf=sector_conf,
        findings=findings,
        vuln_risk=vuln_risk,
        security_like=security_like,
        attack_kw_hits=attack_hits
    )

    if category == "noise":
        scored["reasons"].insert(0, "Classified as noise (low signal)")
        scored["score"] = min(scored["score"], 3.0)

    # IOC extraction + CVE enrichment
    iocs_raw = extract_iocs(text)
    cve_enriched = enrich_cves(iocs_raw.get("cves", [])) if iocs_raw.get("cves") else []

    alert = {
        "category": category,
        "sector": sector_label,
        "intent": intent,
        "sectors": [{"label": sector_label, "confidence": sector_conf}],
        "score": float(scored["score"]),
        "score_reasons": scored["reasons"],
        "findings": [asdict(f) for f in findings],
        "entities": entities,
        "iocs": {"raw": iocs_raw, "cve_enriched": cve_enriched},
        "post": {
            "title": post_meta.get("title"),
            "author": post_meta.get("author"),
            "url": post_meta.get("url"),
            "source": post_meta.get("source"),
            "created_at": post_meta.get("created_at"),
            "text": text,
        }
    }

    if vuln_features is not None:
        alert["vuln_risk"] = vuln_risk

    return alert
