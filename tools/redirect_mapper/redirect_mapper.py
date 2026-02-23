#!/usr/bin/env python3
"""
redirect_mapper.py
Map URL redirect chains using:
  1) HTTP-level redirects (301/302/307/308) via httpx
  2) Browser-level redirects (meta refresh / JavaScript / tracking hops) via Playwright (optional)

Safe-by-default notes:
- Does NOT click elements or submit forms.
- Disables downloads in the browser context.
- Records only navigation + network facts needed for analysis.

Examples:
  python redirect_mapper.py "hxxps[://]storage[.]googleapis[.]com/whilewait/comessuccess[.]html" --browser --screenshot-out evidence/final.png
  python redirect_mapper.py "https://example.com" --browser --har-out evidence/chain.har --json-out out/redirects.json
  python redirect_mapper.py urls.txt --browser --max-hops 20

Prereqs:
  pip install httpx playwright tldextract
  playwright install
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
import time
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

import httpx
import tldextract


# ----------------------------
# Utilities
# ----------------------------

DEFANG_HTTP = {"http://": "hxxp://", "https://": "hxxps://"}


def defang(s: str) -> str:
    if not s:
        return s
    out = s.strip()
    out = out.replace("https://", "hxxps://").replace("http://", "hxxp://")
    # defang dots in hostnames for readability (but keep paths intact)
    try:
        p = urlparse(out.replace("hxxps://", "https://").replace("hxxp://", "http://"))
        if p.netloc:
            host = p.netloc.replace(".", "[.]")
            rebuilt = p._replace(netloc=host).geturl()
            rebuilt = rebuilt.replace("https://", "hxxps://").replace("http://", "hxxp://")
            return rebuilt
    except Exception:
        pass
    return out.replace(".", "[.]")


def refang(s: str) -> str:
    if not s:
        return s
    out = s.strip()
    out = out.replace("[.]", ".").replace("hxxps://", "https://").replace("hxxp://", "http://")
    out = out.replace("hxxps[://]", "https://").replace("hxxp[://]", "http://")
    # common defang pattern: hxxps[://]example[.]com
    out = re.sub(r"^hxxps\[\://\]", "https://", out, flags=re.IGNORECASE)
    out = re.sub(r"^hxxp\[\://\]", "http://", out, flags=re.IGNORECASE)
    return out


def is_probably_url(s: str) -> bool:
    s = s.strip()
    if not s:
        return False
    s = refang(s)
    return s.startswith("http://") or s.startswith("https://")


def read_urls(arg: str) -> List[str]:
    """Accept a URL or a file path containing URLs."""
    if os.path.isfile(arg):
        urls: List[str] = []
        with open(arg, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if is_probably_url(line):
                    urls.append(refang(line))
        return urls
    return [refang(arg)]


def resolve_ip(hostname: str) -> Optional[str]:
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


def normalize_url(u: str) -> str:
    u = refang(u)
    if not re.match(r"^https?://", u, flags=re.IGNORECASE):
        # assume https if scheme missing
        u = "https://" + u
    return u


def domain_parts(host: str) -> Dict[str, str]:
    ext = tldextract.extract(host)
    return {
        "subdomain": ext.subdomain or "",
        "domain": ext.domain or "",
        "suffix": ext.suffix or "",
        "registered_domain": ".".join([p for p in [ext.domain, ext.suffix] if p]) if ext.domain and ext.suffix else host,
    }


# ----------------------------
# Data structures
# ----------------------------

@dataclass
class Hop:
    step: int
    url: str
    url_defanged: str
    method: str
    status_code: Optional[int]
    location: Optional[str]
    location_defanged: Optional[str]
    ip: Optional[str]
    server: Optional[str]
    content_type: Optional[str]
    via: str  # "httpx" or "browser"
    timestamp_utc: float


@dataclass
class Result:
    input_url: str
    input_url_defanged: str
    started_utc: float
    ended_utc: float
    httpx_chain: List[Hop]
    browser_chain: List[Hop]
    final_url: Optional[str]
    final_url_defanged: Optional[str]
    notes: List[str]


# ----------------------------
# HTTPX redirect mapping (server redirects)
# ----------------------------

def map_http_redirects(
    url: str,
    max_hops: int,
    timeout_s: float,
    user_agent: str,
    verify_tls: bool,
    allow_insecure_http: bool,
) -> List[Hop]:
    hops: List[Hop] = []
    started = time.time()

    # We do manual follow to capture every hop deterministically.
    current = normalize_url(url)

    # Optional: block plain HTTP if user wants.
    if (not allow_insecure_http) and current.lower().startswith("http://"):
        raise ValueError("Plain HTTP is disabled. Use --allow-http to permit http:// URLs.")

    headers = {"User-Agent": user_agent, "Accept": "*/*"}
    limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)

    with httpx.Client(
        follow_redirects=False,
        timeout=httpx.Timeout(timeout_s),
        headers=headers,
        verify=verify_tls,
        limits=limits,
    ) as client:
        for i in range(1, max_hops + 1):
            ts = time.time()
            resp = client.request("GET", current)
            parsed = urlparse(str(resp.url))
            ip = resolve_ip(parsed.hostname or "") if parsed.hostname else None

            location = resp.headers.get("location")
            server = resp.headers.get("server")
            ctype = resp.headers.get("content-type")

            hop = Hop(
                step=i,
                url=str(resp.url),
                url_defanged=defang(str(resp.url)),
                method="GET",
                status_code=resp.status_code,
                location=location,
                location_defanged=defang(location) if location else None,
                ip=ip,
                server=server,
                content_type=ctype,
                via="httpx",
                timestamp_utc=ts,
            )
            hops.append(hop)

            # Follow only HTTP redirect status codes
            if resp.status_code in (301, 302, 303, 307, 308) and location:
                next_url = httpx.URL(str(resp.url)).join(location)
                current = str(next_url)
                if (not allow_insecure_http) and current.lower().startswith("http://"):
                    # stop, but record why
                    break
                continue

            # Non-redirect or no Location → stop
            break

    _ = started  # kept in case you want to extend timing per section
    return hops


# ----------------------------
# Browser redirect mapping (meta/js redirects)
# ----------------------------

def map_browser_redirects(
    url: str,
    max_hops: int,
    timeout_s: float,
    user_agent: str,
    verify_tls: bool,
    screenshot_out: Optional[str],
    har_out: Optional[str],
    wait_after_load_ms: int,
    block_third_party: bool,
) -> List[Hop]:
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        raise RuntimeError(
            "Playwright not available. Install with: pip install playwright && playwright install"
        ) from e

    hops: List[Hop] = []
    seen_nav_urls: List[str] = []

    def record_hop(step: int, nav_url: str, status: Optional[int], location: Optional[str], ctype: Optional[str]) -> None:
        ts = time.time()
        parsed = urlparse(nav_url)
        ip = resolve_ip(parsed.hostname or "") if parsed.hostname else None
        server = None  # Playwright doesn't expose "server" header directly without extra work
        hops.append(
            Hop(
                step=step,
                url=nav_url,
                url_defanged=defang(nav_url),
                method="GET",
                status_code=status,
                location=location,
                location_defanged=defang(location) if location else None,
                ip=ip,
                server=server,
                content_type=ctype,
                via="browser",
                timestamp_utc=ts,
            )
        )

    target = normalize_url(url)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context_kwargs: Dict[str, Any] = {
            "user_agent": user_agent,
            "ignore_https_errors": not verify_tls,
            "accept_downloads": False,
        }

        if har_out:
            context_kwargs["record_har_path"] = har_out
            context_kwargs["record_har_content"] = "omit"  # keep evidence lightweight by default

        context = browser.new_context(**context_kwargs)
        page = context.new_page()

        # Optional: reduce noise by blocking third-party requests
        if block_third_party:
            first_party_host = urlparse(target).hostname or ""

            def route_handler(route, request):
                try:
                    req_host = urlparse(request.url).hostname or ""
                    if req_host and first_party_host and req_host != first_party_host:
                        return route.abort()
                except Exception:
                    pass
                return route.continue_()

            page.route("**/*", route_handler)

        # Track navigation responses in main frame
        step_counter = 0

        def on_response(resp):
            nonlocal step_counter
            try:
                req = resp.request
                if not req.is_navigation_request():
                    return
                if req.frame != page.main_frame:
                    return

                nav_url = req.url
                # Prevent duplicate spam
                if seen_nav_urls and nav_url == seen_nav_urls[-1]:
                    return

                step_counter += 1
                seen_nav_urls.append(nav_url)

                status = resp.status
                # Location header if present
                location = resp.headers.get("location")
                ctype = resp.headers.get("content-type")
                record_hop(step_counter, nav_url, status, location, ctype)

                # Stop recording if we exceed max hops; we'll still let page settle
                if step_counter >= max_hops:
                    return
            except Exception:
                return

        page.on("response", on_response)

        # Navigate
        try:
            page.goto(target, wait_until="load", timeout=int(timeout_s * 1000))
        except Exception:
            # Even if load fails, we may still have captured hops.
            pass

        # Give time for meta refresh / JS redirects after load
        if wait_after_load_ms > 0:
            try:
                page.wait_for_timeout(wait_after_load_ms)
            except Exception:
                pass

        # Ensure final URL is recorded even if no nav responses were captured
        final = page.url
        if not seen_nav_urls or (seen_nav_urls and final != seen_nav_urls[-1]):
            step_counter += 1
            seen_nav_urls.append(final)
            record_hop(step_counter, final, None, None, None)

        # Screenshot
        if screenshot_out:
            try:
                os.makedirs(os.path.dirname(screenshot_out) or ".", exist_ok=True)
                page.screenshot(path=screenshot_out, full_page=True)
            except Exception:
                pass

        context.close()
        browser.close()

    return hops


# ----------------------------
# Orchestrator
# ----------------------------

def build_result(
    input_url: str,
    httpx_chain: List[Hop],
    browser_chain: List[Hop],
    started: float,
    ended: float,
    notes: List[str],
) -> Result:
    final_url = None
    if browser_chain:
        final_url = browser_chain[-1].url
    elif httpx_chain:
        final_url = httpx_chain[-1].url

    return Result(
        input_url=input_url,
        input_url_defanged=defang(input_url),
        started_utc=started,
        ended_utc=ended,
        httpx_chain=httpx_chain,
        browser_chain=browser_chain,
        final_url=final_url,
        final_url_defanged=defang(final_url) if final_url else None,
        notes=notes,
    )


def to_jsonable(res: Result) -> Dict[str, Any]:
    d = asdict(res)
    return d


def main() -> int:
    ap = argparse.ArgumentParser(description="Map redirect chains (HTTP + browser).")
    ap.add_argument("target", help="URL or path to a file containing URLs (one per line). Defanged OK.")
    ap.add_argument("--json-out", default=None, help="Write full results to this JSON file.")
    ap.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")

    # HTTP mapping
    ap.add_argument("--max-hops", type=int, default=15, help="Maximum hops to follow/record.")
    ap.add_argument("--timeout", type=float, default=20.0, help="Timeout per request/navigation (seconds).")
    ap.add_argument("--user-agent", default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) redirect_mapper/1.0",
                    help="User-Agent string.")
    ap.add_argument("--no-tls-verify", action="store_true", help="Disable TLS verification (not recommended).")
    ap.add_argument("--allow-http", action="store_true", help="Allow plain HTTP URLs (default blocks).")

    # Browser mapping
    ap.add_argument("--browser", action="store_true", help="Enable Playwright-based mapping (captures JS/meta redirects).")
    ap.add_argument("--wait-after-load-ms", type=int, default=4000,
                    help="Time to wait after page load to catch delayed JS/meta redirects.")
    ap.add_argument("--screenshot-out", default=None, help="Save a full-page screenshot (browser mode).")
    ap.add_argument("--har-out", default=None, help="Save HAR file with network requests (browser mode).")
    ap.add_argument("--block-third-party", action="store_true",
                    help="Abort third-party requests to reduce noise (may break some redirect chains).")

    args = ap.parse_args()

    urls = read_urls(args.target)
    verify_tls = not args.no_tls_verify

    all_results: List[Dict[str, Any]] = []
    exit_code = 0

    for u in urls:
        started = time.time()
        notes: List[str] = []
        httpx_chain: List[Hop] = []
        browser_chain: List[Hop] = []

        try:
            httpx_chain = map_http_redirects(
                u,
                max_hops=args.max_hops,
                timeout_s=args.timeout,
                user_agent=args.user_agent,
                verify_tls=verify_tls,
                allow_insecure_http=args.allow_http,
            )
        except Exception as e:
            notes.append(f"httpx_error: {type(e).__name__}: {e}")

        if args.browser:
            try:
                browser_chain = map_browser_redirects(
                    u,
                    max_hops=args.max_hops,
                    timeout_s=args.timeout,
                    user_agent=args.user_agent,
                    verify_tls=verify_tls,
                    screenshot_out=args.screenshot_out,
                    har_out=args.har_out,
                    wait_after_load_ms=args.wait_after_load_ms,
                    block_third_party=args.block_third_party,
                )
            except Exception as e:
                notes.append(f"browser_error: {type(e).__name__}: {e}")

        ended = time.time()
        result = build_result(u, httpx_chain, browser_chain, started, ended, notes)
        all_results.append(to_jsonable(result))

        # Console summary (safe & readable)
        print("\n=== Redirect Map ===")
        print(f"Input: {defang(u)}")
        if httpx_chain:
            print("\n[HTTP Redirects]")
            for h in httpx_chain:
                loc = f" -> {h.location_defanged}" if h.location_defanged else ""
                sc = h.status_code if h.status_code is not None else "-"
                print(f"  {h.step:02d}. {sc} {h.url_defanged}{loc}")
        else:
            print("\n[HTTP Redirects] (none captured)")

        if args.browser:
            if browser_chain:
                print("\n[Browser Navigations]")
                for h in browser_chain:
                    sc = h.status_code if h.status_code is not None else "-"
                    print(f"  {h.step:02d}. {sc} {h.url_defanged}")
            else:
                print("\n[Browser Navigations] (none captured)")

        print(f"\nFinal: {result.final_url_defanged or '(unknown)'}")
        if notes:
            print("Notes:")
            for n in notes:
                print(f"  - {n}")

    # JSON output
    if args.json_out:
        os.makedirs(os.path.dirname(args.json_out) or ".", exist_ok=True)
        with open(args.json_out, "w", encoding="utf-8") as f:
            if args.pretty:
                json.dump(all_results, f, indent=2, ensure_ascii=False)
            else:
                json.dump(all_results, f, ensure_ascii=False)

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
