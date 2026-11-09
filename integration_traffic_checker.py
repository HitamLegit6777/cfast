#!/usr/bin/env python3
"""Check Ahrefs free traffic overview using Cloudflare Turnstile solve via anti-captcha."""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Optional


ANTI_CAPTCHA_URL = "https://api.anti-captcha.com"
AHR_EFS_URL = "https://ahrefs.com/v4/stGetFreeTrafficOverview"
AHR_BACKLINKS_OVERVIEW_URL = "https://ahrefs.com/v4/stGetFreeBacklinksOverview"
AHR_BACKLINKS_LIST_URL = "https://ahrefs.com/v4/stGetFreeBacklinksList"
AHR_BACKLINK_CHECKER_URL = "https://ahrefs.com/backlink-checker/"
AHR_TRAFFIC_CHECKER_URL = "https://ahrefs.com/traffic-checker/"
TURNSTILE_SITEKEY = "0x4AAAAAAAAzi9ITzSN9xKMi"
CLIENT_KEY = "a54e303995bc3d00e40837e3aa10b4d1"
AHR_CLIENT_VERSION = "release-20260828-bk34873-61edc614c6cb1"
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"
)


@dataclass
class SolverResult:
    task_id: int
    token: str



def post_json(url: str, payload: Dict[str, Any], timeout: int = 30) -> Dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read().decode("utf-8")
        return json.loads(raw)


def get_json(url: str, params: Optional[Dict[str, str]] = None, headers: Optional[Dict[str, str]] = None, timeout: int = 30) -> Dict[str, Any]:
    if params:
        qs = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
        url = f"{url}?{qs}"
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read().decode("utf-8")
        return json.loads(raw)


def create_turnstile_task(
    client_key: str,
    website_url: str,
    site_key: str,
    user_agent: str,
    page_action: str,
    api_base: str,
) -> int:
    payload = {
        "clientKey": client_key,
        "task": {
            "type": "TurnstileTaskProxyless",
            "websiteURL": website_url,
            "websiteKey": site_key,
            "userAgent": user_agent,
            "pageAction": page_action,
        },
    }

    r = post_json(f"{api_base}/createTask", payload)
    if r.get("errorId") != 0:
        raise RuntimeError(f"createTask failed: {r}")
    task_id = r.get("taskId")
    if not isinstance(task_id, int):
        raise RuntimeError(f"createTask no taskId: {r}")
    return task_id


def wait_turnstile_token(
    client_key: str,
    task_id: int,
    api_base: str,
    timeout: int,
    interval: int,
) -> SolverResult:
    start = time.time()
    attempts = 0
    while True:
        attempts += 1
        r = post_json(f"{api_base}/getTaskResult", {
            "clientKey": client_key,
            "taskId": task_id,
        })

        status = r.get("status")
        elapsed = time.time() - start
        if status == "ready":
            solution = r.get("solution", {})
            token = solution.get("token")
            if not token:
                raise RuntimeError(f"task ready but no token: {r}")
            print(f"[turnstile] solved in {elapsed:.1f}s (polls={attempts})", file=sys.stderr)
            return SolverResult(task_id=task_id, token=token)
        if status == "failed":
            raise RuntimeError(f"task failed: {r}")
        if status not in ("processing", "pending"):
            raise RuntimeError(f"unexpected task status '{status}': {r}")

        print(f"[turnstile] {status} ... {elapsed:.0f}s elapsed", file=sys.stderr)
        if time.time() - start >= timeout:
            raise TimeoutError(
                f"task {task_id} not solved within {timeout}s (attempts={attempts})"
            )
        time.sleep(interval)


def solve_turnstile_local(
    website_url: str,
    site_key: str,
    page_action: str,
    api_base: str,
    max_wait: int,
    interval: int,
) -> tuple[str, str]:
    """Solve via the local pure-protocol API. Returns (token, ua).

    The token is bound to the solver profile's UA — the caller MUST replay with
    this exact UA or ahrefs answers InvalidCaptcha.
    """
    payload = {
        "url": website_url,
        "sitekey": site_key,
        "action": page_action,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{api_base.rstrip('/')}/solve",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    start = time.time()
    with urllib.request.urlopen(req, timeout=max_wait) as r:
        result = json.loads(r.read().decode("utf-8"))
    if result.get("status") != 1:
        raise RuntimeError(f"local solver failed: {result}")
    token = result.get("token") or ""
    ua = result.get("ua") or ""
    print(
        f"[turnstile] local pure-protocol solve ok in {time.time()-start:.1f}s",
        file=sys.stderr,
    )
    return token, ua


def solve_turnstile(
    client_key: str,
    website_url: str,
    site_key: str,
    user_agent: str,
    page_action: str,
    api_base: str,
    max_wait: int,
    interval: int,
) -> str:
    print(f"[turnstile] submitting solve task ...", file=sys.stderr)
    task_id = create_turnstile_task(
        client_key=client_key,
        website_url=website_url,
        site_key=site_key,
        user_agent=user_agent,
        page_action=page_action,
        api_base=api_base,
    )
    result = wait_turnstile_token(
        client_key=client_key,
        task_id=task_id,
        api_base=api_base,
        timeout=max_wait,
        interval=interval,
    )
    return result.token


def call_ahrefs(
    domain: str,
    mode: str,
    protocol: Optional[str],
    country: Optional[str],
    captcha_token: str,
    headers: Dict[str, str],
    timeout: int,
) -> Dict[str, Any]:
    payload = {
        "url": domain,
        "mode": mode,
        "protocol": protocol,
        "country": country,
        "captcha": captcha_token,
    }

    # Keep JSON compact exactly like production request.
    query = {
        "input": json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
    }

    return get_json(AHR_EFS_URL, params=query, headers=headers, timeout=timeout)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check ahrefs free traffic overview using anti-captcha Turnstile solving"
    )
    parser.add_argument("--client-key", default=CLIENT_KEY, help="anti-captcha client key (default: hardcoded)")
    parser.add_argument(
        "--domain",
        required=True,
        help="Domain to check in ahrefs traffic checker (example: kliksosmed.id)",
    )
    parser.add_argument(
        "--site-key",
        default=TURNSTILE_SITEKEY,
        help="Cloudflare Turnstile sitekey used by Ahrefs page (default: hardcoded)",
    )
    parser.add_argument(
        "--mode",
        default="subdomains",
        choices=["exact", "subdomains", "phrase", "unknown"],
        help="Ahrefs mode parameter (default: subdomains)",
    )
    parser.add_argument(
        "--protocol",
        default=None,
        help="Optional protocol filter for Ahrefs request (default: null)",
    )
    parser.add_argument(
        "--country",
        default=None,
        help="Optional country filter for Ahrefs request (default: null)",
    )
    parser.add_argument(
        "--user-agent",
        default=DEFAULT_USER_AGENT,
        help="User-Agent used to solve Turnstile and call Ahrefs",
    )
    parser.add_argument(
        "--page-action",
        default="turnstile",
        help="Turnstile pageAction field (default: turnstile)",
    )
    parser.add_argument(
        "--captcha-token",
        help="Optional: reuse existing captcha token instead of solving a new one",
    )
    parser.add_argument(
        "--solver-api",
        default="http://127.0.0.1:8810",
        help="Local pure-protocol solver API (used first when set; empty disables)",
    )
    parser.add_argument(
        "--anti-captcha-api",
        default=ANTI_CAPTCHA_URL,
        help=f"anti-captcha API base URL (default: {ANTI_CAPTCHA_URL})",
    )
    parser.add_argument(
        "--ahrefs-page",
        default=None,
        help="URL opened in browser context while solving + for Referer header (default: built from --domain)",
    )
    parser.add_argument(
        "--max-wait",
        type=int,
        default=120,
        help="Max seconds to wait for anti-captcha solve (default: 120)",
    )
    parser.add_argument(
        "--poll-interval", type=int, default=1,
        help="Polling interval in seconds (default: 1)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="HTTP timeout for each request (default: 60)",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON response",
    )
    parser.add_argument(
        "--save-json",
        help="Optional output file path to save response JSON",
    )
    return parser.parse_args()


def check_traffic(
    domain: str,
    mode: str = "subdomains",
    protocol: Optional[str] = None,
    country: Optional[str] = None,
    captcha_token: Optional[str] = None,
    client_key: str = CLIENT_KEY,
    site_key: str = TURNSTILE_SITEKEY,
    user_agent: str = DEFAULT_USER_AGENT,
    page_action: str = "turnstile",
    api_base: str = ANTI_CAPTCHA_URL,
    solver_api: str = "",
    ahrefs_page: Optional[str] = None,
    max_wait: int = 120,
    interval: int = 1,
    timeout: int = 60,
) -> Dict[str, Any]:
    """Solve Turnstile (if no token) and call Ahrefs free traffic overview."""
    ahrefs_page = ahrefs_page or f"{AHR_TRAFFIC_CHECKER_URL}?input={domain}&mode={mode}"

    captcha = captcha_token
    if not captcha and solver_api:
        captcha, ua = solve_turnstile_local(
            website_url=ahrefs_page,
            site_key=site_key,
            page_action=page_action,
            api_base=solver_api,
            max_wait=max_wait,
            interval=interval,
        )
        user_agent = ua  # session must match: token bound to this UA
    if not captcha:
        captcha = solve_turnstile(
            client_key=client_key,
            website_url=ahrefs_page,
            site_key=site_key,
            user_agent=user_agent,
            page_action=page_action,
            api_base=api_base,
            max_wait=max_wait,
            interval=interval,
        )

    headers = {
        "accept": "*/*",
        "accept-language": "en-GB,en-US;q=0.9,en;q=0.8,id;q=0.7",
        "cache-control": "no-cache",
        "pragma": "no-cache",
        "priority": "u=1, i",
        "referer": ahrefs_page,
        "sec-ch-ua": '"Not=A?Brand";v="99", "Google Chrome";v="151", "Chromium";v="151"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": user_agent,
        "x-client-version": AHR_CLIENT_VERSION,
    }

    return call_ahrefs(
        domain=domain,
        mode=mode,
        protocol=protocol,
        country=country,
        captcha_token=captcha,
        headers=headers,
        timeout=timeout,
    )

def main() -> int:
    args = parse_args()
    ahrefs_page = args.ahrefs_page or f"{AHR_TRAFFIC_CHECKER_URL}?input={args.domain}&mode={args.mode}"

    captcha = args.captcha_token
    if not captcha and args.solver_api:
        captcha, args.user_agent = solve_turnstile_local(
            website_url=ahrefs_page,
            site_key=args.site_key,
            page_action=args.page_action,
            api_base=args.solver_api,
            max_wait=args.max_wait,
            interval=args.poll_interval,
        )
    if not captcha:
        captcha = solve_turnstile(
            client_key=args.client_key,
            website_url=ahrefs_page,
            site_key=args.site_key,
            user_agent=args.user_agent,
            page_action=args.page_action,
            api_base=args.anti_captcha_api,
            max_wait=args.max_wait,
            interval=args.poll_interval,
        )

    headers = {
        "accept": "*/*",
        "accept-language": "en-GB,en-US;q=0.9,en;q=0.8,id;q=0.7",
        "cache-control": "no-cache",
        "pragma": "no-cache",
        "priority": "u=1, i",
        "referer": ahrefs_page,
        "sec-ch-ua": '"Not=A?Brand";v="99", "Google Chrome";v="151", "Chromium";v="151"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": args.user_agent,
        "x-client-version": AHR_CLIENT_VERSION,
    }

    result = call_ahrefs(
        domain=args.domain,
        mode=args.mode,
        protocol=args.protocol,
        country=args.country,
        captcha_token=captcha,
        headers=headers,
        timeout=args.timeout,
    )

    if args.pretty:
        text = json.dumps(result, ensure_ascii=False, indent=2)
    else:
        text = json.dumps(result, ensure_ascii=False)

    print(text)

    if args.save_json:
        with open(args.save_json, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except urllib.error.URLError as e:
        print(f"[network error] {e}", file=sys.stderr)
        raise SystemExit(2)
    except (RuntimeError, TimeoutError) as e:
        print(f"[error] {e}", file=sys.stderr)
        raise SystemExit(3)
