#!/usr/bin/env python3
"""Capture complete /fo/ and /eb/ request payloads for offline crypto reversal.

Saves, per round:
  captures/round_<n>_fo.req   headers (json) + body (raw bytes)
  captures/round_<n>_fo.resp  status + headers + body
  captures/round_<n>_eb.req / .resp
plus captures/summary.json with the ordered flow.

The widget is rendered on a local page with a production-shape sitekey so the
real fingerprint/PoW exchange happens instead of the 3x dummy short-circuit.
"""
import asyncio, json, os, sys, time
from playwright.async_api import async_playwright

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "captures")
SITEKEY = os.environ.get("TS_SITEKEY", "0x4AAAAAAADnPIDROrmt1Wwj")
CHROME = "/root/.cache/ms-playwright/chromium-1248/chrome-linux64/chrome"


def save(name, headers, body):
    path = os.path.join(OUT, name)
    meta = {"headers": headers, "body_hex": body.hex(), "body_len": len(body)}
    open(path + ".json", "w").write(json.dumps(meta, indent=1))
    open(path + ".bin", "wb").write(body)


async def main():
    os.makedirs(OUT, exist_ok=True)
    flow = []
    counter = {"n": 0, "pending": {}}

    async with async_playwright() as p:
        proxy = os.environ.get("TS_PROXY", "")
        launch_kw = dict(
            headless=os.environ.get("TS_HEADLESS", "1") == "1",
            executable_path=CHROME,
            args=["--disable-blink-features=AutomationControlled"],
        )
        if proxy:
            launch_kw["proxy"] = {"server": "http://" + proxy}
        browser = await p.chromium.launch(**launch_kw)
        ctx = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            viewport={"width": 1280, "height": 720},
            locale="en-US",
        )
        page = await ctx.new_page()

        def kind_of(url):
            if "/fo/" in url: return "fo"
            if "/eb/" in url: return "eb"
            return None

        def on_req(r):
            k = kind_of(r.url)
            if not k or r.method != "POST":
                return
            counter["n"] += 1
            n = counter["n"]
            body = b""
            try:
                body = r.post_data_buffer or b""
            except Exception:
                pass
            name = f"round_{n:02d}_{k}.req"
            save(name, dict(r.headers), body)
            counter["pending"][r.url] = (n, k)
            flow.append({"n": n, "kind": k, "dir": "req", "url": r.url, "len": len(body)})
            print(f"[req] {n:02d} {k} len={len(body)}")

        async def on_resp(r):
            k = kind_of(r.url)
            if not k:
                return
            try:
                hdrs = await r.all_headers()
                body = await r.body()
            except Exception:
                return
            n, kk = counter["pending"].get(r.url, (counter["n"], k))
            save(f"round_{n:02d}_{kk}.resp", hdrs, body)
            flow.append({"n": n, "kind": kk, "dir": "resp", "status": r.status,
                         "cf_chl_out": hdrs.get("cf-chl-out", "")[:40],
                         "cf_chl_out_s": hdrs.get("cf-chl-out-s", "")[:40],
                         "body": body[:60].decode("latin-1")})
            print(f"[resp] {n:02d} {kk} status={r.status} cf-chl-out-s={hdrs.get('cf-chl-out-s','')[:20]}")

        page.on("request", on_req)
        page.on("response", lambda r: asyncio.ensure_future(on_resp(r)))

        # Prove which egress the browser actually used: a proxy that is not
        # applied turns every "residential" experiment into a datacenter one.
        try:
            egress = await page.evaluate(
                "async () => { const r = await fetch('https://api.ipify.org?format=json'); return (await r.json()).ip; }"
            )
        except Exception as e:
            egress = f"unknown ({e})"
        print("EGRESS:", egress)

        html = f"""<html><body>
<div class="cf-turnstile" data-sitekey="{SITEKEY}"></div>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async></script>
</body></html>"""
        await page.route("**/tssolver.local/**", lambda r: r.fulfill(body=html, content_type="text/html"))
        await page.goto("https://tssolver.local/", wait_until="domcontentloaded", timeout=30000)
        await asyncio.sleep(8)

        for f in page.frames:
            if "challenges.cloudflare.com" in f.url:
                try:
                    await f.locator("body").click(position={"x": 30, "y": 30}, timeout=5000)
                except Exception:
                    pass
                break

        token = None
        for _ in range(120):
            try:
                token = await page.evaluate(
                    "() => { const e = document.querySelector('[name=cf-turnstile-response]'); return e ? e.value : null; }"
                )
                if token:
                    break
            except Exception:
                pass
            await asyncio.sleep(0.5)
        await asyncio.sleep(4)
        print("TOKEN:", (token or "NONE")[:80])
        flow.append({"token": token})
        open(os.path.join(OUT, "summary.json"), "w").write(json.dumps(flow, indent=1))
        await browser.close()


asyncio.run(main())
