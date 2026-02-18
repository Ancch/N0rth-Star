# backend/app/main.py
from __future__ import annotations

import asyncio
import json
import os
import time
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.responses import HTMLResponse, StreamingResponse
from sqlmodel import Session, select

from backend.app.auth import require_api_key
from backend.app.collector import collect_source, load_sources_yaml, normalize_posts
from backend.app.db import engine, get_session, init_db
from backend.app.models import Alert, Asset, Post, Run, ScanFinding
from backend.app.pipeline_store import upsert_post_and_alert
from backend.app.reporter import build_report_context
from backend.app.scanner import passive_scan_url
from backend.app.scraper import scrape_url  # returns ScrapeResult
from jinja2 import Template

app = FastAPI(title="North Star API", version="1.0")


# -----------------------------
# Config toggles (safe defaults)
# -----------------------------
AUTO_COLLECT = os.getenv("NORTHSTAR_AUTO_COLLECT", "1") == "1"
AUTO_SCAN = os.getenv("NORTHSTAR_AUTO_SCAN", "1") == "1"
AUTO_RETRAIN = os.getenv("NORTHSTAR_AUTO_RETRAIN", "0") == "1"  # default OFF
COLLECT_INTERVAL_SECONDS = int(os.getenv("NORTHSTAR_COLLECT_INTERVAL", "60"))
SCAN_INTERVAL_SECONDS = int(os.getenv("NORTHSTAR_SCAN_INTERVAL", "120"))
RETRAIN_INTERVAL_SECONDS = int(os.getenv("NORTHSTAR_RETRAIN_INTERVAL", "1800"))  # 30 min


# -----------------------------
# Startup
# -----------------------------
@app.on_event("startup")
async def startup():
    init_db()

    # Background loops (automation)
    if AUTO_COLLECT:
        asyncio.create_task(auto_collector_loop())
    if AUTO_SCAN:
        asyncio.create_task(auto_scan_loop())
    if AUTO_RETRAIN:
        asyncio.create_task(auto_retrain_loop())


@app.get("/health")
def health():
    return {"ok": True, "auto": {"collect": AUTO_COLLECT, "scan": AUTO_SCAN, "retrain": AUTO_RETRAIN}}


# -----------------------------
# Live dashboard (HTML)
# -----------------------------
@app.get("/live")
def live():
    html = Path("backend/app/templates/live.html").read_text(encoding="utf-8")
    return HTMLResponse(html)


# -----------------------------
# DEMO JSON FEED (for local demo_forum scraping)
# -----------------------------
@app.get("/demo/feed.json")
def demo_feed():
    now = datetime.utcnow().isoformat() + "Z"
    return {
        "items": [
            {
                "title": "telecom creds for sale",
                "author": "x",
                "created_at": now,
                "url": "local://2",
                "text": "selling telecom db creds. password=hunter2",
            },
            {
                "title": "upi attack planning",
                "author": "y",
                "created_at": now,
                "url": "local://3",
                "text": "planning ddos on upi gateway tonight",
            },
            {
                "title": "private key leak",
                "author": "z",
                "created_at": now,
                "url": "local://4",
                "text": "-----BEGIN PRIVATE KEY-----\nMIIE...FAKE\n-----END PRIVATE KEY-----",
            },
            {
                "title": "vulnerability report",
                "author": "secops",
                "created_at": now,
                "url": "local://5",
                "text": "CVE discussion on exposed service",
            },
            {"title": "noise", "author": "n", "created_at": now, "url": "local://6", "text": "football match tonight was great"},
        ]
    }


# -----------------------------
# URL -> scrape -> ML -> store -> return
# -----------------------------
@app.post("/scan/url")
def scan_url(payload: dict, ok=Depends(require_api_key), session: Session = Depends(get_session)):
    url = payload.get("url")
    if not url:
        return {"ok": False, "error": "Missing url"}

    res = scrape_url(url)

    # If fetch fails: do NOT poison ML with error strings
    if not res.ok:
        alert = {
            "category": "fetch_failed",
            "sector": "other",
            "intent": {"label": "irrelevant", "confidence": 1.0},
            "sectors": [{"label": "other", "confidence": 1.0}],
            "score": 3.0,
            "score_reasons": [f"URL fetch failed: {res.error}"],
            "findings": [],
            "entities": [],
            "iocs": {"raw": {"cves": [], "ips": [], "domains": [], "emails": []}, "cve_enriched": []},
            "post": {"title": None, "author": None, "url": url, "source": "url_scan", "created_at": None, "text": ""},
        }
        return {"ok": False, "url": url, "fetch": {"error": res.error, "used_insecure_ssl": res.used_insecure_ssl}, "alert": alert}

    # Store so it appears in /alerts + SSE
    post_id, alert_id = upsert_post_and_alert(
        session,
        source="url_scan",
        url=url,
        title=None,
        author=None,
        created_at=None,
        text=res.text,
        vuln_features=None,
    )

    return {
        "ok": True,
        "url": url,
        "fetch": {"status_code": res.status_code, "used_insecure_ssl": res.used_insecure_ssl, "note": res.error},
        "post_id": post_id,
        "alert_id": alert_id,
    }


# -----------------------------
# Ingest single post (manual)
# -----------------------------
@app.post("/ingest/demo")
def ingest_demo(payload: dict, ok=Depends(require_api_key), session: Session = Depends(get_session)):
    created_at = payload.get("created_at")
    dt = None
    if created_at:
        dt = datetime.fromisoformat(created_at.replace("Z", "+00:00")).replace(tzinfo=None)

    post_id, alert_id = upsert_post_and_alert(
        session,
        source=payload.get("source", "demo_forum"),
        url=payload.get("url", "local://demo"),
        title=payload.get("title"),
        author=payload.get("author"),
        created_at=dt,
        text=payload.get("text", ""),
        vuln_features=payload.get("vuln_features"),
    )
    return {"post_id": post_id, "alert_id": alert_id}


# -----------------------------
# Sources + Collector (manual trigger)
# -----------------------------
@app.get("/sources")
def list_sources(ok=Depends(require_api_key)):
    return {"sources": load_sources_yaml()}


@app.post("/collect/run")
def collect_run(ok=Depends(require_api_key), session: Session = Depends(get_session)):
    run = Run(kind="collect", started_at=datetime.utcnow(), stats_json={})
    session.add(run)
    session.commit()
    session.refresh(run)

    inserted_posts = 0
    created_alerts = 0
    errors = []

    for cfg in load_sources_yaml():
        if not cfg.get("enabled", True):
            continue
        try:
            posts = collect_source(cfg)
            normalized = normalize_posts(posts)
            for p in normalized:
                _post_id, alert_id = upsert_post_and_alert(
                    session,
                    source=p["source"],
                    url=p["url"],
                    title=p["title"],
                    author=p["author"],
                    created_at=p["created_at"],
                    text=p["text"],
                    vuln_features=cfg.get("vuln_features"),
                )
                if alert_id != -1:
                    inserted_posts += 1
                    created_alerts += 1
        except Exception as e:
            errors.append({"source": cfg.get("name"), "error": str(e)})

    run.ended_at = datetime.utcnow()
    run.stats_json = {"inserted_posts": inserted_posts, "created_alerts": created_alerts, "errors": errors}
    session.add(run)
    session.commit()

    return {"ok": True, "inserted_posts": inserted_posts, "created_alerts": created_alerts, "errors": errors}


# -----------------------------
# Alerts API
# -----------------------------
@app.get("/alerts")
def list_alerts(min_score: float = 0.0, session: Session = Depends(get_session)):
    q = select(Alert).where(Alert.score >= min_score).order_by(Alert.created_at.desc())
    alerts = session.exec(q).all()
    out = []
    for a in alerts:
        p = session.get(Post, a.post_id) if a.post_id else None
        out.append(
            {
                "id": a.id,
                "score": a.score,
                "sector": a.sector,
                "category": a.category,
                "intent": a.intent,
                "intent_confidence": a.intent_confidence,
                "status": a.status,
                "created_at": a.created_at.isoformat(timespec="seconds"),
                "post": {
                    "id": p.id if p else None,
                    "source": p.source if p else None,
                    "url": p.url if p else None,
                    "title": p.title if p else None,
                }
                if p
                else None,
                "asset_id": a.asset_id,
                "vuln_risk": {"score": a.vuln_risk_score, "method": a.vuln_risk_method} if a.vuln_risk_score is not None else None,
            }
        )
    return {"alerts": out}


@app.get("/top")
def top_threats(limit: int = 5, session: Session = Depends(get_session)):
    alerts = session.exec(select(Alert).order_by(Alert.score.desc()).limit(limit)).all()
    out = []
    for a in alerts:
        p = session.get(Post, a.post_id) if a.post_id else None
        out.append(
            {
                "id": a.id,
                "score": a.score,
                "sector": a.sector,
                "category": a.category,
                "intent": a.intent,
                "created_at": a.created_at.isoformat(timespec="seconds"),
                "title": (p.title if p else None),
                "url": (p.url if p else None),
                "source": (p.source if p else None),
                "asset_id": a.asset_id,
            }
        )
    return {"top": out}


@app.get("/trends")
def trends(days: int = 7, session: Session = Depends(get_session)):
    since = datetime.utcnow() - timedelta(days=days)
    alerts = session.exec(select(Alert).where(Alert.created_at >= since)).all()
    by_day, by_sector, by_category = {}, {}, {}
    for a in alerts:
        d = a.created_at.date().isoformat()
        by_day[d] = by_day.get(d, 0) + 1
        by_sector[a.sector] = by_sector.get(a.sector, 0) + 1
        by_category[a.category] = by_category.get(a.category, 0) + 1
    return {"range_days": days, "alerts_per_day": by_day, "sector_counts": by_sector, "category_counts": by_category}


# -----------------------------
# Assets + Passive scan run (manual)
# -----------------------------
@app.post("/assets/add")
def add_asset(payload: dict, ok=Depends(require_api_key), session: Session = Depends(get_session)):
    value = payload["value"]
    existing = session.exec(select(Asset).where(Asset.value == value)).first()
    if existing:
        return {"ok": True, "asset_id": existing.id}

    a = Asset(kind=payload.get("kind", "url"), value=value, owner=payload.get("owner"), tags=payload.get("tags", {}))
    session.add(a)
    session.commit()
    session.refresh(a)
    return {"ok": True, "asset_id": a.id}


@app.get("/assets")
def list_assets(ok=Depends(require_api_key), session: Session = Depends(get_session)):
    assets = session.exec(select(Asset).order_by(Asset.created_at.desc())).all()
    return {"assets": [a.model_dump() for a in assets]}


@app.post("/scan/run")
def scan_run(ok=Depends(require_api_key), session: Session = Depends(get_session)):
    run = Run(kind="scan", started_at=datetime.utcnow(), stats_json={})
    session.add(run)
    session.commit()
    session.refresh(run)

    assets = session.exec(select(Asset).where(Asset.active == True)).all()
    created_alerts = 0
    findings_written = 0

    for a in assets:
        if a.kind != "url":
            continue

        res = passive_scan_url(a.value)

        if res.missing_headers:
            sf = ScanFinding(
                asset_id=a.id,
                type="missing_security_headers",
                severity=min(10, 3 + len(res.missing_headers)),
                evidence_json={"missing": res.missing_headers, "status": res.http_status, "url": res.url},
            )
            session.add(sf)
            findings_written += 1

        if res.tls_days_left is not None and res.tls_days_left <= 14:
            sf = ScanFinding(asset_id=a.id, type="tls_expiring_soon", severity=8, evidence_json={"tls_days_left": res.tls_days_left, "url": res.url})
            session.add(sf)
            findings_written += 1

        if res.server_header:
            sf = ScanFinding(asset_id=a.id, type="server_disclosure", severity=4, evidence_json={"server": res.server_header, "url": res.url})
            session.add(sf)
            findings_written += 1

        session.commit()

        if res.missing_headers or (res.tls_days_left is not None and res.tls_days_left <= 14):
            vuln_features = {
                "cvss": 6.8 if res.missing_headers else 7.5,
                "internet_exposed": True,
                "asset_criticality": (a.tags.get("criticality") if isinstance(a.tags, dict) else "medium") or "medium",
                "patch_age_days": 30,
                "known_exploit": False,
                "env": (a.tags.get("env") if isinstance(a.tags, dict) else "prod") or "prod",
                "auth_required": False,
                "attack_surface": "web",
            }

            text = f"Passive scan findings for {a.value}: missing_headers={len(res.missing_headers)}, tls_days_left={res.tls_days_left}, server={res.server_header}"
            alert_obj = __import__("ml.pipeline", fromlist=["build_alert"]).build_alert(text, vuln_features=vuln_features)

            al = Alert(
                asset_id=a.id,
                post_id=None,
                category="vulnerability",
                sector="other",
                intent="discussion",
                intent_confidence=0.6,
                score=float(alert_obj["score"]),
                score_reasons={"reasons": alert_obj.get("score_reasons", []) + [f"Scan url: {a.value}"]},
                status="open",
                created_at=datetime.utcnow(),
                vuln_risk_score=float(alert_obj["vuln_risk"]["score"]) if alert_obj.get("vuln_risk") else None,
                vuln_risk_method=alert_obj.get("vuln_risk", {}).get("method") if alert_obj.get("vuln_risk") else None,
            )
            session.add(al)
            session.commit()
            created_alerts += 1

    run.ended_at = datetime.utcnow()
    run.stats_json = {"assets": len(assets), "created_alerts": created_alerts, "findings_written": findings_written}
    session.add(run)
    session.commit()

    return {"ok": True, "assets": len(assets), "created_alerts": created_alerts, "findings_written": findings_written}


# -----------------------------
# Reports
# -----------------------------
@app.get("/report/html")
def report_html(days: int = 7, ok=Depends(require_api_key), session: Session = Depends(get_session)):
    ctx = build_report_context(session, days=days, limit=80)
    tpl = Template(Path("backend/app/templates/report.html").read_text(encoding="utf-8"))
    return HTMLResponse(tpl.render(**ctx))


# -----------------------------
# SSE stream (live dashboard)
# -----------------------------
@app.get("/alerts/stream")
def alerts_stream():
    def gen():
        last_id = 0
        last_hb = 0.0
        yield "event: hello\ndata: {}\n\n"

        while True:
            with Session(engine) as session:
                new_alerts = session.exec(select(Alert).where(Alert.id > last_id).order_by(Alert.id.asc())).all()
                for a in new_alerts:
                    p = session.get(Post, a.post_id) if a.post_id else None
                    payload = {
                        "id": a.id,
                        "score": a.score,
                        "sector": a.sector,
                        "category": a.category,
                        "intent": a.intent,
                        "created_at": a.created_at.isoformat(timespec="seconds"),
                        "title": (p.title if p else None) or (f"Scan alert: asset {a.asset_id}" if a.asset_id else None),
                        "url": (p.url if p else None),
                        "source": (p.source if p else None),
                        "asset_id": a.asset_id,
                    }
                    last_id = a.id
                    yield f"event: alert\ndata: {json.dumps(payload)}\n\n"

            now = time.time()
            if now - last_hb >= 5:
                last_hb = now
                yield f": heartbeat {int(now)}\n\n"

            time.sleep(1)

    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "Connection": "keep-alive"})


# =============================
# AUTOMATION LOOPS (Background)
# =============================
async def auto_collector_loop():
    # Wait for app boot
    await asyncio.sleep(3)
    while True:
        try:
            with Session(engine) as session:
                inserted = 0
                created = 0
                errors = []

                for cfg in load_sources_yaml():
                    if not cfg.get("enabled", True):
                        continue
                    try:
                        posts = collect_source(cfg)
                        normalized = normalize_posts(posts)
                        for p in normalized:
                            _post_id, alert_id = upsert_post_and_alert(
                                session,
                                source=p["source"],
                                url=p["url"],
                                title=p["title"],
                                author=p["author"],
                                created_at=p["created_at"],
                                text=p["text"],
                                vuln_features=cfg.get("vuln_features"),
                            )
                            if alert_id != -1:
                                inserted += 1
                                created += 1
                    except Exception as e:
                        errors.append({"source": cfg.get("name"), "error": str(e)})

                # log a Run row so you can show “continuous monitoring”
                run = Run(kind="auto_collect", started_at=datetime.utcnow(), ended_at=datetime.utcnow(), stats_json={"inserted_posts": inserted, "created_alerts": created, "errors": errors})
                session.add(run)
                session.commit()

                if inserted or created:
                    print(f"🚀 [AUTO_COLLECT] inserted={inserted} alerts={created}")
                if errors:
                    print(f"⚠️ [AUTO_COLLECT] errors={len(errors)}")

        except Exception as e:
            print("❌ [AUTO_COLLECT] fatal:", e)

        await asyncio.sleep(COLLECT_INTERVAL_SECONDS)


async def auto_scan_loop():
    await asyncio.sleep(5)
    while True:
        try:
            with Session(engine) as session:
                assets = session.exec(select(Asset).where(Asset.active == True)).all()
                created_alerts = 0

                for a in assets:
                    if a.kind != "url":
                        continue

                    res = passive_scan_url(a.value)

                    notable = bool(res.missing_headers) or (res.tls_days_left is not None and res.tls_days_left <= 14)
                    if not notable:
                        continue

                    vuln_features = {
                        "cvss": 6.8 if res.missing_headers else 7.5,
                        "internet_exposed": True,
                        "asset_criticality": (a.tags.get("criticality") if isinstance(a.tags, dict) else "medium") or "medium",
                        "patch_age_days": 30,
                        "known_exploit": False,
                        "env": (a.tags.get("env") if isinstance(a.tags, dict) else "prod") or "prod",
                        "auth_required": False,
                        "attack_surface": "web",
                    }

                    text = f"Auto passive scan findings for {a.value}: missing_headers={len(res.missing_headers)}, tls_days_left={res.tls_days_left}, server={res.server_header}"
                    alert_obj = __import__("ml.pipeline", fromlist=["build_alert"]).build_alert(text, vuln_features=vuln_features)

                    al = Alert(
                        asset_id=a.id,
                        post_id=None,
                        category="vulnerability",
                        sector="other",
                        intent="discussion",
                        intent_confidence=0.6,
                        score=float(alert_obj["score"]),
                        status="open",
                        created_at=datetime.utcnow(),
                        vuln_risk_score=float(alert_obj["vuln_risk"]["score"]) if alert_obj.get("vuln_risk") else None,
                        vuln_risk_method=alert_obj.get("vuln_risk", {}).get("method") if alert_obj.get("vuln_risk") else None,
                    )
                    session.add(al)
                    created_alerts += 1

                if created_alerts:
                    session.commit()
                    print(f"🛰️ [AUTO_SCAN] created_alerts={created_alerts}")

                run = Run(kind="auto_scan", started_at=datetime.utcnow(), ended_at=datetime.utcnow(), stats_json={"assets": len(assets), "created_alerts": created_alerts})
                session.add(run)
                session.commit()

        except Exception as e:
            print("❌ [AUTO_SCAN] fatal:", e)

        await asyncio.sleep(SCAN_INTERVAL_SECONDS)


async def auto_retrain_loop():
    """
    Optional. Default OFF (NORTHSTAR_AUTO_RETRAIN=0).
    If you enable it, it retrains your small TF-IDF models periodically.
    """
    await asyncio.sleep(10)
    while True:
        try:
            print("🧠 [AUTO_RETRAIN] running...")
            import subprocess

            subprocess.run(["python", "ml/train_intent.py"], check=False)
            subprocess.run(["python", "ml/train_sector.py"], check=False)
            print("🧠 [AUTO_RETRAIN] done")
        except Exception as e:
            print("❌ [AUTO_RETRAIN] fatal:", e)

        await asyncio.sleep(RETRAIN_INTERVAL_SECONDS)
