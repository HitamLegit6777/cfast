#!/usr/bin/env python3
"""Turnstile bundle deobfuscator.

Two layers, both self-describing so this keeps working when Cloudflare rotates
the build hash:

  1. bootstrap bundle  (/turnstile/v0/b/<hash>/api.js) — has an atob-based
     decoder with a fixed seed baked into the minified function.
  2. challenge VM      (the inline <script> inside the /rch/ HTML response) —
     same decoder shape, different seed, ~3900 encoded calls.

The seed is not a constant we hardcode: it is parsed out of the decoder body
(`var f=v.atob(W),S=1075,...`). Everything downstream uses that parsed seed.
"""
import base64
import re
import sys


def find_decoders(src):
    """Every atob-based decoder declaration in src, as (name, seed)."""
    out = []
    pat = re.compile(
        r"var\s+([A-Za-z_$][\w$]*)\s*=\s*\(function\([A-Za-z_$][\w$]*\)\s*\{[\s\S]{0,700}?atob\([^)]*\)\s*,\s*[A-Za-z_$][\w$]*\s*=\s*(\d+)"
    )
    for m in pat.finditer(src):
        out.append((m.group(1), int(m.group(2))))
    return out


def score(strings):
    """Printable-ASCII ratio over the decoded set: a wrong seed yields bytes."""
    if not strings:
        return 0.0
    good = total = 0
    for s in strings:
        for ch in s:
            total += 1
            if 32 <= ord(ch) < 127:
                good += 1
    return good / total if total else 0.0


def find_decoder(src):
    best = (None, None, 0.0, [])
    for name, seed in find_decoders(src):
        calls = re.findall(re.escape(name) + r"\(`([^`]*)`\)", src)
        if len(calls) < 50:
            continue
        vals = []
        for c in calls:
            try:
                vals.append(decode(c, seed))
            except Exception:
                pass
        sc = score(vals)
        if sc > best[2]:
            best = (name, seed, sc, vals)
    return best[0], best[1], best[2], best[3]


def decode(encoded, seed):
    """Port of the bundle's decoder: rolling 16-bit xor over a base64 payload."""
    raw = base64.b64decode(encoded).decode("latin-1")
    data = [ord(c) & 0xFF for c in raw]
    r = seed
    out = []
    i = 0
    n = len(data)
    while i < n:
        r = ((r << 8) | (r >> 8)) & 0xFFFF
        m = data[i] ^ (r >> 8)
        i += 1
        if m == 255:
            r = ((r << 8) | (r >> 8)) & 0xFFFF
            m = data[i] ^ (r >> 8)
            i += 1
            r = ((r << 8) | (r >> 8)) & 0xFFFF
            m |= (data[i] ^ (r >> 8)) << 8
            i += 1
        out.append(m)
    return "".join(chr(c) for c in out)


def dump(src, label="", out_path=None):
    name, seed, sc, vals = find_decoder(src)
    if not name:
        print(f"[{label}] no decoder found", file=sys.stderr)
        return None
    print(f"[{label}] decoder={name} seed={seed} printable={sc:.3f} strings={len(vals)}")
    if out_path:
        open(out_path, "w").write("\n".join(sorted(set(vals))))
        print(f"[{label}] wrote {out_path}")
    return vals


if __name__ == "__main__":
    for path in sys.argv[1:]:
        src = open(path, encoding="utf-8", errors="replace").read()
        base = path.rsplit("/", 1)[-1].split(".")[0]
        dump(src, path, out_path=f"strings_{base}.txt")
