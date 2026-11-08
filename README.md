# cfast — Cloudflare Turnstile Pure-Protocol Solver

Solves Cloudflare Turnstile widgets with **zero browser processes**. No Chrome,
no Xvfb, no headless flag — a Rust binary with a built-in JS virtual machine
replays a recorded browser profile and computes the proof-of-work answer in
pure HTTP.

```
┌─────────────┐   GET  /fo/4/eb/4  ┌──────────────────────────┐
│ challenge   │ ─────────────────► │ challenges.cloudflare.com│
│ (Rust VM)   │ ◄───────────────── │    2MB challenge VM      │
└─────────────┘   cf-chl-out-s:    └──────────────────────────┘
        ▲         token comes back in a response header
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
# Option 1: direct CLI
./challenge --page "https://target.com/" /tmp/out --solve \
  --fingerprint profile_fast.json \
  --sitekey "0x4AAAAAAA..." --action "managed" --blank-page

# Option 2: 2captcha-compatible HTTP API
python3 solver_api.py                # listens :8810
curl localhost:8810/solve -H 'Content-Type: application/json' \
  -d '{"url":"https://target.com/","sitekey":"0x4AAA...","action":"login"}'
# → {"status":1,"token":"1.xxxx","elapsed":16.7,"ua":"..."}

# Option 3: async (createTask/getTaskResult shape)
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

Requires Rust 1.98 (pinned), CMake, clang/libclang.

```bash
git clone https://github.com/chris124567/cfsolve
cd cfsolve
cargo build --release --bin challenge
cp target/release/challenge ./challenge
```

This repo ships:

| File | What |
|---|---|
| `challenge` | Prebuilt linux-x64 binary (61 MB) |
| `profile_fast.json` + `profile_fast/` | Fast-timing Safari profile (ready) |
| `profile_safari/` | Stock Safari-iOS profile (slower timings) |
| `solver_api.py` | HTTP API wrapper (2captcha shape) |
| `deobf.py` | Standalone Turnstile VM string-table dumper |
| `capture_full.py` | Live /fo/+/eb/ payload capture harness |

## LICENSE

MIT (cfsolve upstream) — this repo only packages the build + wrapper.
