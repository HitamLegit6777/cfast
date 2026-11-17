# cfast — Cloudflare Pure-Protocol Solver (Turnstile + Managed Challenge)

Solves Cloudflare **Turnstile widgets** and **managed challenges** with **zero
browser processes**. No Chrome, no Xvfb, no headless flag — a Rust binary with
a built-in JS virtual machine replays a recorded browser profile and computes
the proof-of-work answer in pure HTTP.

```
┌─────────────┐   GET  /fo/4/eb/4   ┌──────────────────────────┐
│ challenge   │ ─────────────────►  │ challenges.cloudflare.com│
│ (Rust VM)   │ ◄─────────────────  │    2MB challenge VM      │
└─────────────┘   cf-chl-out-s:     └──────────────────────────┘
        ▲          token in a response header
        │
        │  managed challenge: GET /cdn-cgi/challenge-platform/.../orchestrate/...
        │  ──► cf_clearance=<value>  (the cookie that opens the site)
        │
   solver_api.py :8810 (2captcha-compatible API)
```

## Benchmark (VPS 8 vCPU, Singapore — measured live)

| Metric | Value |
|---|---|
| Solve time (single, cold) | **15.7 – 21.1 s** (avg 18.2 s) |
| Solve time (fast profile) | **15.6 – 17.9 s** (avg 16.4 s) |
| Throughput (8 concurrent) | 37.8 s wall for 8 solves → **0.21 tok/s** |
| Memory per solve | **~73 MB RSS** (peak), daemon idler |
| Daemon idle RAM (API only) | ~14 MB |
| Total disk | 61 MB (challenge binary) |
| Success rate (demo sitekey) | **5/5, 3/3, verified live** |

**Comparison with a browser farm at the same site**:

| Approach | Time | RAM | Browser needed |
|---|---|---|---|
| cfsolve (this repo) | 16–18 s | 73 MB | **No** |
| Headless Chrome farm | 18–30 s | 350+ MB per tab | Yes |
| Anti-captcha API | 12–60 s |– |– (they use browser farms themselves) |

The latency is dominated by Cloudflare's own challenge round-trips, not local
computation: page fetch → fingerprint POST → proof POST → token. Each round
trip is ~200 ms from SG; the heavy part is swc deobfuscation of the 617 KB VM
(Challenge script rotates).

## Usage

```bash
# Option 1: Turnstile widget (direct CLI)
./challenge --page "https://target.com/" /tmp/out --solve \
  --fingerprint profile_fast.json \
  --sitekey "0x4AAAAAAA..." --action "managed" --blank-page

# Option 2: managed challenge (Cloudflare "Just a moment..." interstitial)
./challenge --page "https://target.com/" /tmp/out --solve \
  --fingerprint profile_safari.json
# → cf_clearance=<value>     (last line of stdout)

# Option 3: 2captcha-compatible HTTP API (Turnstile)
python3 solver_api.py                # listens :8810
curl localhost:8810/solve -H 'Content-Type: application/json' \
  -d '{"url":"https://target.com/","sitekey":"0x4AAA...","action":"login"}'
# → {"status":1,"token":"1.xxxx","elapsed":16.7,"ua":"..."}

# Option 4: async (createTask/getTaskResult shape)
curl localhost:8810/in.php  -d '{"url":"...","sitekey":"..."}'
poll: GET localhost:8810/res.php?action=get&id=<task_id>
```

## Session binding — read this or your token gets rejected

A Turnstile token is bound to **(hostname, user-agent of the profile)**. Replay
with the exact UA the API returns (`ua` field), from any IP. If you send a
different UA the target's `siteverify` will reject it (`InvalidCaptcha`).

```
solver result  →  UA: Mozilla/5.0 (iPhone; CPU iPhone OS 18_7...) Safari/604.1
replay request →  same UA header, same sitekey, any IP
```

If you need a **specific** UA (Windows-Chrome etc.), record a matching profile
with `capture-proxy` (see `docs/capture-profile.md`) — the profile is the
device personality, not the answer sheet.

## Building

Requires Rust 1.99 (pinned), CMake, clang/libclang. `vendor/` carries the
patched `wreq`/`btls-sys`/`http2` crates (the crates.io builds lack the
trust-anchor knobs).

```bash
git clone https://github.com/HitamLegit6777/cfast.git
cd cfast/source
cargo build --release --bin challenge
cp target/release/challenge ../challenge
```

This repo ships:

| File | What |
|---|---|
| `challenge` | Prebuilt linux-x64 binary (~24 MB) |
| `source/` | Full Rust source (oxc parser, vendored deps) |
| `profile_fast.json` + `profile_fast/` | Fast-timing Safari profile (ready) |
| `profile_safari/` | Stock Safari-iOS profile (slower timings) |
| `solver_api.py` | HTTP API wrapper (2captcha shape, Turnstile only) |
| `deobf.py` | Standalone Turnstile VM string-table dumper |
| `capture_full.py` | Live /fo/+/eb/ payload capture harness |

## Managed challenge notes

- The binary prints `cf_clearance=<value>` (last stdout line) when a managed
  challenge page clears; exit code is 0 on success.
- The cookie is bound to **the profile's UA + the solver's egress IP**. Replay
  it from the same host with the same UA; sending it from a different IP or
  with a different UA restarts the challenge.
- Some challenge shapes issue `cf_clearance` on the **second orchestrator
  POST**, before the clearance form is submitted. cfast ingests that cookie
  directly; submitting the form afterwards is still attempted (its answer may
  be a fresh challenge).
- Fingerprint `answers` files must sit next to the fingerprint JSON: fix the
  `answers` / `challenge_page_answers` fields to bare filenames when moving
  profiles between directories.
- If a challenge responds `probe N matches no known collector`, retry — the
  orchestrator script rotates per request and most retries succeed.
- Since `v1.2.0-managed`, runner detection also reads the decoded challenge
  tree, where the VM is installed as
  `return key = 0, <helper>(<opcode>, <run>, new <Class>(p), …)` instead of
  `return <run>(new <Class>(p), pc, key, [])`. Older builds failed those
  challenges with `expected one program runner, found 0`.

## LICENSE

MIT (cfsolve upstream) — this repo only packages the build + wrapper.
