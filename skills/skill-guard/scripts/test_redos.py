#!/usr/bin/env python3
"""
ReDoS / pathological-input fuzz test for skill-guard.

A scanner reads attacker-controlled files. If one of its own regexes can be driven
into catastrophic backtracking, a hostile skill could hang the audit (a denial of
service against the very tool meant to protect you). This test feeds large
pathological inputs crafted to stress every unbounded quantifier in the pattern
set, runs the REAL CLI in a subprocess under a hard wall-clock timeout, and fails
if the scan does not finish quickly.

Run:  python test_redos.py     (exit 0 = no pathological slowdown)
No network, no third-party deps.
"""
import sys, os, tempfile, shutil, subprocess, time
from pathlib import Path

HERE = Path(__file__).parent
SCANNER = HERE / "skill_guard.py"
TIMEOUT_S = 15          # a linear scan of these inputs finishes in well under 1s
N = 200_000             # input size that would make an O(n^2) regex take seconds

# Each payload targets a specific unbounded quantifier in skill_guard's patterns.
PAYLOADS = {
    # \bcurl\b[^\n|]*\|...  — long run with no pipe forces backtracking
    "curl.md":      "curl " + "a" * N,
    # BEGIN [A-Z ]*PRIVATE KEY — many starts, long [A-Z ]* run, no terminator
    "pem.md":       ("BEGIN " * 200) + ("A" * N),
    # yaml.load((?![^)]*Loader) — negative lookahead scans to EOF, many starts
    "yaml.py":      ("yaml.load(" * 500) + ("x" * N),
    # injection lazy quantifiers [^.]{0,30}? etc. across a huge punctuation-free run
    "inject.md":    "say " + ("everything is " * (N // 14)),
    # secret-file [^.\n]{0,40}? before a near-miss target
    "secret.md":    ("read " + "z" * N + " .ssh"),
    # homoglyph \w+ over a giant token, plus invisible-char spam
    "homoglyph.md": ("а" + "a") * (N // 2),
    "zw.md":        ("​" * 50_000) + "\n" + ("‮" * 50_000),
    # pipe-to-shell near-miss: curl ... | with no sh/bash
    "pipe.sh":      "curl " + ("x" * N) + " | ",
}

def build(tmp):
    d = tmp / "fuzz-skill"
    d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text("---\nname: fuzz\ndescription: fuzz\n---\n", encoding="utf-8")
    for fn, body in PAYLOADS.items():
        (d / fn).write_text(body, encoding="utf-8")
    return d

def run():
    tmp = Path(tempfile.mkdtemp(prefix="skillguard_redos_"))
    try:
        build(tmp)
        env = dict(os.environ, PYTHONUTF8="1")
        t0 = time.perf_counter()
        try:
            subprocess.run([sys.executable, str(SCANNER), "scan", str(tmp), "--quiet"],
                           capture_output=True, timeout=TIMEOUT_S, env=env)
        except subprocess.TimeoutExpired:
            print("FAIL: scan did not finish within %ss on pathological input "
                  "-> possible catastrophic backtracking (ReDoS)." % TIMEOUT_S)
            return 1
        dt = time.perf_counter() - t0
        # A healthy linear/near-linear scan is fast; flag worrying slowness early.
        if dt > 5.0:
            print("FAIL: scan took %.1fs on %d-byte inputs - too slow, tighten a quantifier." % (dt, N))
            return 1
        print("PASS - pathological inputs scanned in %.2fs (no ReDoS, no hang)." % dt)
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

if __name__ == "__main__":
    sys.exit(run())
