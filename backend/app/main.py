# backend/app/main.py
from __future__ import annotations
from backend.app.active_scanner import active_scan_url
from fastapi import FastAPI, Depends
from fastapi.responses import StreamingResponse, HTMLResponse
from sqlmodel import Session, select
from datetime import datetime, timedelta
import json, time
from pathlib import Path
from backend.app.simulator import generate_attack_logs
from backend.app.db import init_db, get_session, engine
from backend.app.auth import require_api_key
from backend.app.models import Alert, Post, Asset, ScanFinding, Run
from backend.app.pipeline_store import upsert_post_and_alert
from backend.app.collector import load_sources_yaml, collect_source, normalize_posts
from backend.app.scanner import passive_scan_url
from backend.app.reporter import build_report_context
from backend.app.scraper import scrape_url
from jinja2 import Template

app = FastAPI(title="North Star API", version="1.0")

@app.get("/live")
def live():
    html = Path("backend/app/templates/live.html").read_text(encoding="utf-8")
    return HTMLResponse(html)

@app.on_event("startup")
def startup():
    init_db()


@app.get("/health")
def health():
    return {"ok": True}


# -----------------------------
# DEMO JSON FEED
# -----------------------------
@app.get("/demo/feed.json")
def demo_feed():
    now = datetime.utcnow().isoformat() + "Z"
    return {
        "items": [
            {"title": "telecom creds for sale", "author": "x", "created_at": now, "url": "local://2",
             "text": "selling telecom db creds. password=hunter2"},
            {"title": "upi attack planning", "author": "y", "created_at": now, "url": "local://3",
             "text": "planning ddos on upi gateway tonight"},
            {"title": "private key leak", "author": "z", "created_at": now, "url": "local://4",
             "text": "-----BEGIN PRIVATE KEY-----\nMIIE...FAKE\n-----END PRIVATE KEY-----"},
            {"title": "vulnerability report", "author": "secops", "created_at": now, "url": "local://5",
             "text": "CVE discussion on exposed service"},
            {"title": "noise", "author": "n", "created_at": now, "url": "local://6",
             "text": "football match tonight was great"},
        ]
    }


# -----------------------------
# URL scrape -> store post/alert
# -----------------------------
@app.post("/scan/url")
def scan_url(payload: dict, ok=Depends(require_api_key), session: Session = Depends(get_session)):
    url = payload.get("url")
    if not url:
        return {"ok": False, "error": "Missing url"}

    res = scrape_url(url)

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

    post_id, alert_id = upsert_post_and_alert(
        session,
        source="url_scan",
        url=url,
        title=None,
        author=None,
        created_at=None,
        text=res.text,
        vuln_features=None
    )

    return {
        "ok": True,
        "url": url,
        "fetch": {"status_code": res.status_code, "used_insecure_ssl": res.used_insecure_ssl, "note": res.error},
        "post_id": post_id,
        "alert_id": alert_id
    }

@app.post("/scan/active")
def scan_active(payload: dict, ok=Depends(require_api_key), session: Session = Depends(get_session)):
    url = payload.get("url")
    if not url:
        return {"ok": False, "error": "Missing url"}

    res = active_scan_url(url)

    # Create a vulnerability alert if notable
    notable = [f for f in res.findings if f.get("severity", 0) >= 4]
    vuln_features = None
    if notable:
        vuln_features = {
            "cvss": 7.5,
            "internet_exposed": True,
            "asset_criticality": "medium",
            "patch_age_days": 30,
            "known_exploit": False,
            "env": "prod",
            "auth_required": False,
            "attack_surface": "web",
        }

    text = f"Active scan for {url}: findings={len(res.findings)} notes={'; '.join(res.notes)}"
    for f in res.findings[:12]:
        text += f"\n- {f['type']}: {f.get('evidence')}"

    post_id, alert_id = upsert_post_and_alert(
        session,
        source="active_scan",
        url=url,
        title="active scan result",
        author="scanner",
        created_at=None,
        text=text,
        vuln_features=vuln_features
    )

    return {"ok": res.ok, "url": url, "status": res.status, "post_id": post_id, "alert_id": alert_id, "findings": res.findings, "notes": res.notes}

@app.post("/simulate/attacks")
def simulate_attacks(ok=Depends(require_api_key), session: Session = Depends(get_session)):
    logs = generate_attack_logs(20)

    inserted = 0

    for log in logs:
        _, alert_id = upsert_post_and_alert(
            session,
            source="simulator",
            url=log["url"],
            title=log["title"],
            author=log["author"],
            created_at=log["created_at"],
            text=log["text"],
            vuln_features=None
        )
        if alert_id != -1:
            inserted += 1

    return {"ok": True, "generated": inserted}

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
# Sources
# -----------------------------
@app.get("/sources")
def list_sources(ok=Depends(require_api_key)):
    return {"sources": load_sources_yaml()}


# -----------------------------
# Collector (FAST MODE)
# -----------------------------
@app.post("/collect/run")
def collect_run(
    max_seconds: int = 20,
    ok=Depends(require_api_key),
    session: Session = Depends(get_session)
):
    """
    Fast collector:
    - Stops after max_seconds total.
    - Skips any source that errors/times out.
    - Returns partial results quickly (demo-safe).
    """
    started = time.time()

    run = Run(kind="collect", started_at=datetime.utcnow(), stats_json={})
    session.add(run); session.commit(); session.refresh(run)

    inserted_posts = 0
    created_alerts = 0
    errors = []
    sources_ok = 0
    sources_skipped = 0

    for cfg in load_sources_yaml():
        if not cfg.get("enabled", True):
            sources_skipped += 1
            continue

        # Global deadline: avoid hanging the endpoint
        if time.time() - started > max_seconds:
            errors.append({"source": "collector", "error": f"Stopped early: max_seconds={max_seconds} hit"})
            break

        name = cfg.get("name")

        try:
            posts = collect_source(cfg)
            normalized = normalize_posts(posts)

            sources_ok += 1

            for p in normalized:
                _post_id, alert_id = upsert_post_and_alert(
                    session,
                    source=p["source"],
                    url=p["url"],
                    title=p["title"],
                    author=p["author"],
                    created_at=p["created_at"],
                    text=p["text"],
                    vuln_features=cfg.get("vuln_features")
                )
                # upsert returns -1 when deduped
                if alert_id != -1:
                    inserted_posts += 1
                    created_alerts += 1

        except Exception as e:
            errors.append({"source": name, "error": str(e)})

    run.ended_at = datetime.utcnow()
    run.stats_json = {
        "inserted_posts": inserted_posts,
        "created_alerts": created_alerts,
        "errors": errors,
        "max_seconds": max_seconds,
        "sources_ok": sources_ok,
        "sources_skipped": sources_skipped
    }
    session.add(run); session.commit()

    return {"ok": True, "inserted_posts": inserted_posts, "created_alerts": created_alerts, "errors": errors, "max_seconds": max_seconds}


# -----------------------------
# Alerts APIs
# -----------------------------
@app.get("/alerts")
def list_alerts(min_score: float = 0.0, session: Session = Depends(get_session)):
    q = select(Alert).where(Alert.score >= min_score).order_by(Alert.created_at.desc())
    alerts = session.exec(q).all()
    out = []
    for a in alerts:
        p = session.get(Post, a.post_id) if a.post_id else None
        out.append({
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
            } if p else None,
            "asset_id": a.asset_id,
            "vuln_risk": {"score": a.vuln_risk_score, "method": a.vuln_risk_method} if a.vuln_risk_score is not None else None
        })
    return {"alerts": out}


@app.get("/top")
def top_threats(limit: int = 5, session: Session = Depends(get_session)):
    alerts = session.exec(select(Alert).order_by(Alert.score.desc()).limit(limit)).all()
    out = []
    for a in alerts:
        p = session.get(Post, a.post_id) if a.post_id else None
        out.append({
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
        })
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
# Assets + Scan (unchanged)
# -----------------------------
@app.post("/assets/add")
def add_asset(payload: dict, ok=Depends(require_api_key), session: Session = Depends(get_session)):
    value = payload["value"]
    existing = session.exec(select(Asset).where(Asset.value == value)).first()
    if existing:
        return {"ok": True, "asset_id": existing.id}

    a = Asset(kind=payload.get("kind", "url"), value=value, owner=payload.get("owner"), tags=payload.get("tags", {}))
    session.add(a); session.commit(); session.refresh(a)
    return {"ok": True, "asset_id": a.id}


@app.get("/assets")
def list_assets(ok=Depends(require_api_key), session: Session = Depends(get_session)):
    assets = session.exec(select(Asset).order_by(Asset.created_at.desc())).all()
    return {"assets": [a.model_dump() for a in assets]}


@app.post("/scan/run")
def scan_run(ok=Depends(require_api_key), session: Session = Depends(get_session)):
    run = Run(kind="scan", started_at=datetime.utcnow(), stats_json={})
    session.add(run); session.commit(); session.refresh(run)

    assets = session.exec(select(Asset).where(Asset.active == True)).all()
    created_alerts = 0
    findings_written = 0

    for a in assets:
        if a.kind != "url":
            continue

        res = passive_scan_url(a.value)

        if res.missing_headers:
            sf = ScanFinding(asset_id=a.id, type="missing_security_headers",
                             severity=min(10, 3 + len(res.missing_headers)),
                             evidence_json={"missing": res.missing_headers, "status": res.http_status, "url": res.url})
            session.add(sf); findings_written += 1

        if res.tls_days_left is not None and res.tls_days_left <= 14:
            sf = ScanFinding(asset_id=a.id, type="tls_expiring_soon", severity=8,
                             evidence_json={"tls_days_left": res.tls_days_left, "url": res.url})
            session.add(sf); findings_written += 1

        if res.server_header:
            sf = ScanFinding(asset_id=a.id, type="server_disclosure", severity=4,
                             evidence_json={"server": res.server_header, "url": res.url})
            session.add(sf); findings_written += 1

        session.commit()

    run.ended_at = datetime.utcnow()
    run.stats_json = {"assets": len(assets), "created_alerts": created_alerts, "findings_written": findings_written}
    session.add(run); session.commit()

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
# SSE stream
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

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "Connection": "keep-alive"})
