#!/usr/bin/env python3
"""Turnstile pure-protocol solver API — cfsolve backend, no browser, no X, no Xvfb.

Endpoints (2captcha-compatible shape):
  GET  /health                  -> ok
  POST /in.php                  -> {"status":1,"request":"<task_id>"}  (json for simplicity)
  GET  /res.php?action=get&id=  -> {"status":1,"request":"<token>"} | {"status":0,...}
  POST /solve                   -> synchronous; {"status":1,"token":...} | {"status":0}

Every solve runs `challenge` (Rust, builtin JS VM + recorded browser profile).
No Chrome, no Xvfb — proven: zero child processes, zero window deps.
"""
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import uuid

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BIN = os.environ.get("TS_BIN", "/root/remaker/tssolver/challenge")
PROFILE = os.environ.get("TS_PROFILE", "/tmp/cfsolve/profiles/safari-26-ios.json")
PORT = int(os.environ.get("TS_PORT", "8810"))

_tasks: dict[str, dict] = {}
_lock = threading.Lock()


def _profile_ua(path: str) -> str:
    """Token validity is bound to the profile's exact UA: replay MUST use it."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for k, v in ((data.get("transport") or {}).get("headers") or {}).items():
            if k.lower() == "user-agent":
                return v
    except Exception:
        pass
    return ""


def _solve_sync(url: str, sitekey: str, action: str = "", cdata: str = "", proxy: str = "", timeout: float = 120.0) -> dict:
    if not os.path.isfile(BIN):
        return {"status": 0, "error": "challenge binary missing"}
    if not os.path.isfile(PROFILE):
        return {"status": 0, "error": "profile missing"}
    if not url or not sitekey:
        return {"status": 0, "error": "MISSING_SITEKEY_OR_URL"}

    workdir = tempfile.mkdtemp(prefix="tss-")
    target = os.path.join(workdir, "run")
    cmd = [BIN, "--page", url, target, "--solve",
           "--fingerprint", PROFILE, "--sitekey", sitekey, "--blank-page"]
    if action:
        cmd += ["--action", action]
    if cdata:
        cmd += ["--cdata", cdata]
    if proxy:
        cmd += ["--proxy", proxy if "://" in proxy else "http://" + proxy]

    t0 = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        shutil.rmtree(workdir, ignore_errors=True)
        return {"status": 0, "error": "TIMEOUT"}
    elapsed = round(time.monotonic() - t0, 2)

    token = ""
    for line in reversed(proc.stdout.splitlines()):
        line = line.strip()
        if line.startswith(".") or (line.startswith("1.") and len(line) > 100):
            token = line
            break
    shutil.rmtree(workdir, ignore_errors=True)
    if token:
        return {"status": 1, "token": token, "elapsed": elapsed, "ua": _profile_ua(PROFILE)}
    err = (proc.stderr or proc.stdout or "unknown").strip().splitlines()[-1][:200]
    return {"status": 0, "error": err, "elapsed": elapsed}


def _spawn(task_id, kwargs):
    result = _solve_sync(**kwargs)
    with _lock:
        _tasks[task_id] = {"done": True, **result}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/health"):
            return self._json({"ok": True, "mode": "pure-protocol", "browser": "none"})
        if self.path.startswith("/res.php") or self.path.startswith("/res"):
            from urllib.parse import urlparse, parse_qs
            q = parse_qs(urlparse(self.path).query)
            tid = (q.get("id") or [""])[0]
            with _lock:
                t = _tasks.get(tid)
            if not t:
                return self._json({"status": 0, "error": "NOT_FOUND"})
            if not t.get("done"):
                return self._json({"status": 0, "error": "CAPCHA_NOT_READY"})
            if t.get("status") == 1:
                out = {"status": 1, "request": t["token"]}
                if t.get("ua"):
                    out["user_agent"] = t["ua"]
                return self._json(out)
            return self._json({"status": 0, "error": t.get("error", "ERROR")})
        return self._json({"status": 0, "error": "UNKNOWN_ROUTE"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw or b"{}")
        except Exception:
            return self._json({"status": 0, "error": "BAD_JSON"})

        if self.path.startswith("/in.php") or self.path.startswith("/solve"):
            url = body.get("url") or body.get("pageurl") or ""
            sitekey = body.get("sitekey") or ""
            action = body.get("action") or ""
            cdata = body.get("cdata") or body.get("cData") or ""
            proxy = body.get("proxy") or ""
            sync = self.path.startswith("/solve")
            if sync:
                return self._json(_solve_sync(url, sitekey, action, cdata, proxy,
                                              float(body.get("timeout") or 120)))
            tid = str(uuid.uuid4())
            with _lock:
                _tasks[tid] = {"done": False}
            threading.Thread(target=_spawn, args=(tid, dict(url=url, sitekey=sitekey,
                                                            action=action, cdata=cdata,
                                                            proxy=proxy)), daemon=True).start()
            return self._json({"status": 1, "request": tid})
        return self._json({"status": 0, "error": "UNKNOWN_ROUTE"})


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"ts-solver api on :{PORT} bin={BIN} profile={PROFILE}")
    srv.serve_forever()
