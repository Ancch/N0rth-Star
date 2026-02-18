from __future__ import annotations
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import requests
from urllib.parse import urljoin

DEFAULT_TIMEOUT = 12

COMMON_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.env",
    "/.git/config",
    "/.DS_Store",
    "/openapi.json",
    "/swagger",
    "/swagger/index.html",
    "/api/docs",
    "/admin",
    "/wp-login.php",
]

SEC_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

@dataclass
class ActiveScanResult:
    url: str
    ok: bool
    status: Optional[int]
    findings: List[Dict[str, Any]]
    notes: List[str]

def _safe_request(method: str, url: str, verify_ssl: bool = True) -> requests.Response:
    return requests.request(
        method=method,
        url=url,
        timeout=DEFAULT_TIMEOUT,
        allow_redirects=True,
        headers={"User-Agent": "NorthStarScanner/1.0"},
        verify=verify_ssl,
    )

def active_scan_url(url: str) -> ActiveScanResult:
    findings: List[Dict[str, Any]] = []
    notes: List[str] = []

    resp = None
    used_insecure = False
    try:
        resp = _safe_request("GET", url, verify_ssl=True)
    except requests.exceptions.SSLError:
        used_insecure = True
        notes.append("SSL verify failed; used insecure mode for scan.")
        resp = _safe_request("GET", url, verify_ssl=False)
    except Exception as e:
        return ActiveScanResult(url=url, ok=False, status=None, findings=[], notes=[f"Fetch failed: {e}"])

    base_headers = {k.lower(): v for k, v in resp.headers.items()}
    missing = [h for h in SEC_HEADERS if h not in base_headers]
    if missing:
        findings.append({
            "type": "missing_security_headers",
            "severity": min(10, 3 + len(missing)),
            "evidence": {"missing": missing, "status": resp.status_code}
        })

    server = base_headers.get("server")
    powered = base_headers.get("x-powered-by")
    if server or powered:
        findings.append({
            "type": "fingerprint_headers",
            "severity": 3,
            "evidence": {"server": server, "x_powered_by": powered}
        })

    for path in COMMON_PATHS:
        target = urljoin(url.rstrip("/") + "/", path.lstrip("/"))
        try:
            r = _safe_request("HEAD", target, verify_ssl=not used_insecure)
            st = r.status_code
            if st in (200, 206):
                findings.append({
                    "type": "interesting_path",
                    "severity": 6 if path in ("/.env", "/.git/config") else 4,
                    "evidence": {"path": path, "url": target, "status": st}
                })
            elif st in (401, 403):
                findings.append({
                    "type": "restricted_path",
                    "severity": 3,
                    "evidence": {"path": path, "url": target, "status": st}
                })
        except Exception:
            continue

    return ActiveScanResult(url=url, ok=True, status=resp.status_code, findings=findings, notes=notes)
