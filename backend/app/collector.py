# backend/app/collector.py
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import time
import json

import requests
import yaml
import feedparser


SOURCES_YAML_PATH = Path("backend/app/sources.yaml")


# -----------------------------
# Helpers
# -----------------------------
def _utcnow_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _get_nested(obj: Any, path: str) -> Any:
    """
    Simple dot-path getter.
    Example: path="items" or "data.items" or "a.0.b" (supports list indexes).
    """
    if not path:
        return obj
    cur = obj
    for part in path.split("."):
        if cur is None:
            return None
        if isinstance(cur, list):
            try:
                idx = int(part)
                cur = cur[idx]
            except Exception:
                return None
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def _parse_dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    # Accepts Z, timezone offsets, or plain ISO
    try:
        # normalize Z
        s2 = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s2)
        # store naive UTC-ish
        return dt.replace(tzinfo=None)
    except Exception:
        return None


def _requests_fetch(
    url: str,
    *,
    timeout: int = 20,
    retries: int = 3,
    backoff_base: float = 0.8,
    headers: Optional[Dict[str, str]] = None,
) -> Tuple[bool, bytes, Optional[str]]:
    """
    Robust fetch with retries + exponential backoff.
    Returns (ok, content_bytes, error_string)
    """
    sess = requests.Session()
    hdrs = {
        "User-Agent": "NorthStarCollector/1.0 (+defensive-osint)",
        "Accept": "*/*",
    }
    if headers:
        hdrs.update(headers)

    last_err = None
    for attempt in range(retries + 1):
        try:
            r = sess.get(url, headers=hdrs, timeout=timeout)
            if r.status_code >= 400:
                last_err = f"HTTP {r.status_code}"
                raise RuntimeError(last_err)
            return True, r.content, None
        except Exception as e:
            last_err = str(e)
            if attempt < retries:
                sleep_s = backoff_base * (2 ** attempt)
                time.sleep(sleep_s)
            else:
                break
    return False, b"", last_err


# -----------------------------
# Public API used by main.py
# -----------------------------
def load_sources_yaml() -> List[Dict[str, Any]]:
    if not SOURCES_YAML_PATH.exists():
        return []
    data = yaml.safe_load(SOURCES_YAML_PATH.read_text(encoding="utf-8")) or {}
    sources = data.get("sources") or []
    # normalize defaults
    out = []
    for s in sources:
        if not isinstance(s, dict):
            continue
        s.setdefault("enabled", True)
        s.setdefault("timeout_seconds", 20)
        s.setdefault("retries", 2)
        s.setdefault("backoff_base", 0.8)
        s.setdefault("max_items", 50)
        out.append(s)
    return out


def collect_source(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Collect raw items from a source config.
    Returns list of raw post dicts with keys:
      title, author, created_at, url, text, source
    """
    name = cfg.get("name", "unknown")
    url = cfg.get("url")
    method = (cfg.get("method") or "rss").lower()

    if not url:
        return []

    ok, content, err = _requests_fetch(
        url,
        timeout=int(cfg.get("timeout_seconds", 20)),
        retries=int(cfg.get("retries", 2)),
        backoff_base=float(cfg.get("backoff_base", 0.8)),
        headers=cfg.get("headers"),
    )

    if not ok:
        # raise so caller can record error per-source
        raise RuntimeError(err or "fetch_failed")

    max_items = int(cfg.get("max_items", 50))

    if method == "json":
        payload = json.loads(content.decode("utf-8", errors="ignore"))
        items_path = cfg.get("json_items_path", "items")
        items = _get_nested(payload, items_path) or []
        if not isinstance(items, list):
            return []

        title_k = cfg.get("json_title_key", "title")
        url_k = cfg.get("json_url_key", "url")
        author_k = cfg.get("json_author_key", "author")
        time_k = cfg.get("json_time_key", "created_at")
        text_k = cfg.get("json_text_key", "text")

        out = []
        for it in items[:max_items]:
            if not isinstance(it, dict):
                continue
            out.append({
                "source": name,
                "title": it.get(title_k),
                "url": it.get(url_k),
                "author": it.get(author_k),
                "created_at": it.get(time_k),
                "text": it.get(text_k) or "",
            })
        return out

    if method == "rss":
        feed = feedparser.parse(content)
        out = []
        for e in (feed.entries or [])[:max_items]:
            link = getattr(e, "link", None) or getattr(e, "id", None)
            title = getattr(e, "title", None)
            author = getattr(e, "author", None)

            # prefer published; fallback updated
            published = getattr(e, "published", None) or getattr(e, "updated", None)

            # best-effort text
            summary = getattr(e, "summary", None) or ""
            # sometimes content is richer than summary
            if getattr(e, "content", None):
                try:
                    summary = e.content[0].value
                except Exception:
                    pass

            out.append({
                "source": name,
                "title": title,
                "url": link,
                "author": author,
                "created_at": published,
                "text": summary or "",
            })
        return out

    if method == "exploitdb_csv":
        # ExploitDB Git repo mirror: CSV contains exploit metadata.
        # We convert each row into "post-like" text for your pipeline.
        text = content.decode("utf-8", errors="ignore")
        lines = [ln for ln in text.splitlines() if ln.strip()]
        if not lines:
            return []

        header = lines[0].split(",")
        # We only take the newest max_items rows from the end to keep it lightweight.
        data_lines = lines[-max_items:]

        out = []
        for ln in data_lines:
            parts = ln.split(",")
            if len(parts) < 6:
                continue
            row = dict(zip(header, parts))
            # Common fields in exploitdb csv mirrors: id, file, description, date, author, type, platform, port...
            title = (row.get("description") or row.get("Description") or "ExploitDB entry").strip()
            eid = (row.get("id") or row.get("ID") or "").strip()
            date = (row.get("date") or row.get("Date") or "").strip()
            platform = (row.get("platform") or row.get("Platform") or "").strip()
            etype = (row.get("type") or row.get("Type") or "").strip()
            link = None
            if eid:
                link = f"https://www.exploit-db.com/exploits/{eid}"

            body = f"{title}\nType: {etype}\nPlatform: {platform}\nDate: {date}\nSource: ExploitDB CSV"

            out.append({
                "source": name,
                "title": title,
                "url": link or url,
                "author": row.get("author") or row.get("Author"),
                "created_at": date,
                "text": body,
            })
        return out

    raise ValueError(f"Unknown method: {method}")


def normalize_posts(raw_posts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Convert raw posts to canonical dict expected by upsert_post_and_alert.
    Ensures:
      source, url, title, author, created_at (datetime|None), text (str)
    """
    out: List[Dict[str, Any]] = []
    for p in raw_posts:
        src = p.get("source") or "unknown"
        url = p.get("url") or f"local://{src}/{_utcnow_iso()}"
        title = p.get("title")
        author = p.get("author")
        dt = p.get("created_at")
        created_at = dt if isinstance(dt, datetime) else _parse_dt(str(dt)) if dt else None
        text = p.get("text") or ""

        # keep it safe and small-ish
        if isinstance(text, bytes):
            text = text.decode("utf-8", errors="ignore")
        text = str(text)
        if len(text) > 20000:
            text = text[:20000] + "\n...[truncated]"

        out.append({
            "source": src,
            "url": url,
            "title": title,
            "author": author,
            "created_at": created_at,
            "text": text,
        })
    return out
