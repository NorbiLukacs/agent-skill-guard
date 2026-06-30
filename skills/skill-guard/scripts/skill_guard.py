#!/usr/bin/env python3
"""
skill-guard - a static, deterministic security auditor for AI agent "skills".

Why it exists: most "vet this skill" tools are pure-markdown methodologies - an
LLM reads the skill and judges it. That has three *structural* blind spots an LLM
cannot fix by being smarter:

  A. Invisible Unicode  - zero-width / bidi-override / Tag-block / homoglyph
                          characters vanish or fragment in tokenization, so an
                          LLM literally cannot see hidden instructions. This
                          scanner reads BYTES, so it can.
  C. Post-install drift - a skill vetted "safe" today can be silently swapped by
                          an update tomorrow. `baseline` + `drift` catch that.
  D. Code vs docs       - bundled .py/.js/.sh get traced for network / exec /
                          secret-access / destructive ops / path traversal.

It is deliberately conservative: it reports CANDIDATES for human review, never a
final "MALICIOUS" verdict. A clean report is necessary, not sufficient - pair it
with reading the raw text and (for survivors) an independent adversarial agent
(see SKILL.md). A capability in a tool that legitimately needs it is normal; the
question is always whether the skill's STATED PURPOSE justifies the capability.

Pure standard library. No network calls. Never spawns a child process. Read-only except `baseline`,
which writes a single JSON fingerprint file where you tell it to. The source is
pure-ASCII (hidden-char signatures are built with chr()) so the tool passes its
own hidden-char audit.

Usage:
  skill_guard.py scan  <dir> [<dir> ...] [--quiet] [--json] [--no-scripts] [--exclude GLOB]
  skill_guard.py baseline <dir> [<dir> ...] --out baseline.json
  skill_guard.py drift <dir> [<dir> ...] --baseline baseline.json [--json]

Exit codes: 0 = nothing to review - 1 = findings/drift present - 2 = usage error
"""
import sys, os, re, json, argparse, hashlib, fnmatch, unicodedata
from pathlib import Path

SCRIPT_EXTS = {".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts",
               ".tsx", ".jsx", ".bat", ".cmd", ".ps1", ".rb", ".pl", ".php", ".exe"}
TEXT_EXTS = {".md", ".markdown", ".mdx", ".txt", ".rst"}
SKIP_PARTS = {"__pycache__", ".git", "node_modules", ".venv", "venv"}
RANK = {"critical": 0, "warn": 1, "review": 2, "info": 3}

# --- A. INVISIBLE / DECEPTIVE UNICODE --------------------------------------
# Built with chr(0x..) so this source file is pure-ASCII and the scanner does NOT
# flag its OWN signature table for hidden characters. (codepoint, label, severity)
_INVIS_DEFS = [
    (0x200B, "ZERO-WIDTH SPACE", "critical"), (0x200C, "ZERO-WIDTH NON-JOINER", "warn"),
    (0x200D, "ZERO-WIDTH JOINER", "critical"), (0x200E, "LEFT-TO-RIGHT MARK", "warn"),
    (0x200F, "RIGHT-TO-LEFT MARK", "warn"),    (0x2060, "WORD JOINER", "critical"),
    (0x00AD, "SOFT HYPHEN", "critical"),       (0xFEFF, "BOM / ZW NO-BREAK SPACE", "warn"),
    (0x2028, "LINE SEPARATOR", "warn"),        (0x2029, "PARAGRAPH SEPARATOR", "warn"),
    (0x202A, "LRE", "warn"), (0x202B, "RLE", "warn"), (0x202C, "PDF", "warn"),
    (0x202D, "LRO (bidi override)", "critical"), (0x202E, "RLO (bidi override)", "critical"),
    (0x2066, "LRI", "warn"), (0x2067, "RLI", "warn"),
    (0x2068, "FSI", "warn"), (0x2069, "PDI", "warn"),
]
ZWJ = chr(0x200D)
INVISIBLE = {chr(cp): (label, sev) for cp, label, sev in _INVIS_DEFS}

def _is_emoji(ch):
    o = ord(ch)
    return (0x1F000 <= o <= 0x1FAFF) or (0x2600 <= o <= 0x27BF) or o in (0xFE0F, 0x2640, 0x2642)

def scan_invisible(text):
    """Return list of (severity, label) for hidden/deceptive characters."""
    out = []
    for i, ch in enumerate(text):
        if ch in INVISIBLE:
            label, sev = INVISIBLE[ch]
            if ch == ZWJ:  # benign-emoji ZWJ exception
                prev = text[i-1] if i else ""
                nxt = text[i+1] if i+1 < len(text) else ""
                if _is_emoji(prev) or _is_emoji(nxt):
                    continue
            out.append((sev, "hidden char U+%04X %s" % (ord(ch), label)))
        elif 0xE0000 <= ord(ch) <= 0xE007F:
            out.append(("critical", "UNICODE TAG char (hidden ASCII smuggling)"))
    # homoglyph / mixed-script: a token mixing Latin with Cyrillic/Greek letters
    for m in re.finditer(r"\w+", text, re.UNICODE):
        w = m.group()
        scripts = set()
        for c in w:
            if not c.isalpha():
                continue
            if c.isascii():
                scripts.add("Latin")
            else:
                try:
                    scripts.add(unicodedata.name(c).split(" ")[0])
                except ValueError:
                    scripts.add("?")
        if "Latin" in scripts and (scripts & {"CYRILLIC", "GREEK", "?"}):
            out.append(("warn", "mixed-script token '%s' (possible homoglyph spoof)" % w))
    seen, uniq = set(), []
    for s in out:
        if s not in seen:
            seen.add(s); uniq.append(s)
    return uniq

# Secret/dangerous-token fragments split with + so the scanner does not flag its
# OWN signature table when you audit skill-guard. Each equals its obvious literal.
_SSH = r"\." + r"ssh"
_ENV = r"\." + r"env"
_RSA = r"id_" + r"rsa"
_ED = r"id_" + r"ed25519"
_REMOVE_ITEM = "Remove-" + "Item"

# --- REVIEWER-SUBVERSION / PROMPT-INJECTION (tuned: low false-positive) -----
# Patterns require an imperative + target, so prose like "Use when asked to..."
# or "When auditing this image" does NOT match.
INJECTION = [
    (r"ignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|prompts?|messages?|context|rules?)", "critical", "override-instructions"),
    (r"disregard\s+(?:all\s+|the\s+|your\s+)?(?:previous|prior|above|system|user|earlier)\b", "critical", "override-instructions"),
    (r"(?:do\s*not|don'?t|never)\s+(?:tell|inform|warn|alert|reveal\s+to|disclose\s+to|report\s+to)\s+(?:the\s+)?(?:user|human|operator|reviewer)", "critical", "suppress-from-user"),
    (r"(?:when|if)\s+(?:you\s+are\s+|you'?re\s+|being\s+)?(?:audited|reviewed|inspected|vetted|scanned|checked\s+for\s+safety)\b[^.]{0,60}?(?:say|report|claim|respond|reply|output|return|answer)", "critical", "behave-differently-when-reviewed"),
    (r"(?:say|report|claim|respond\s+(?:with|that)|tell\s+them|reply)\s+[^.]{0,30}?(?:it'?s|this\s+is|everything\s+is|i\s+am)?\s*(?:safe|clean|benign|harmless|trusted|no\s+(?:risk|threat|issue))", "critical", "claim-safe"),
    (r"(?:conceal|hide|obscure|suppress|omit)\s+(?:this|the|any|all)\s+(?:from\s+the\s+user|finding|instruction|behaviou?r|output|detail)", "critical", "concealment"),
    (r"you\s+(?:must|should|shall|will)\s+(?:now\s+)?(?:act\s+as|pretend\s+to\s+be|roleplay|impersonate|become)\b", "warn", "role-override"),
    # NB: we do NOT flag the bare word for data theft - security skills (this one
    # included) discuss it legitimately. We flag behaviours, not topics.
    (r"(?:send|upload|post|transmit|leak|forward|ex" + r"filtrate)\s+(?:the\s+|all\s+)?(?:user'?s?|their|your)\s+(?:data|files?|secrets?|credentials?|keys?|environment|browsing|history|contacts?)\b", "critical", "steal-user-data"),
    (r"(?:print|cat|read|upload|send|post|transmit|copy|curl|scp)\s+[^.\n]{0,40}?(?:" + _ENV + r"\b|" + _SSH + r"\b|" + _RSA + r"|" + _ED + r"|private\s+key|\.aws[/\\]credentials|[/\\]etc[/\\]passwd)", "critical", "secret-file-access"),
    (r"\bcurl\b[^\n|]*\|\s*(?:sh|bash|zsh)\b|\bwget\b[^\n|]*\|\s*(?:sh|bash)\b", "critical", "pipe-to-shell"),
    (r"(?:base64\s+(?:-d|--decode)|atob\s*\(|fromCharCode)", "warn", "obfuscation/decode"),
]

# --- D. CODE INDICATORS (scripts) ------------------------------------------
# Signature substrings are assembled with "a" + "b" splits so the scanner's own
# pattern table does not self-match when you audit skill-guard itself.
def _j(*parts): return "".join(parts)
CODE = {
    "network":     ("warn",   [r"\brequests\.(?:get|post|put|patch|request|Session)\b", r"\burllib\b",
                               r"\bhttp\.client\b", r"\bsocket\.(?:socket|create_connection|connect)\b",
                               r"\bfetch\s*\(", r"\baxios\b", r"XML" + r"HttpRequest",
                               r"\.openConnection\(", r"\bweb" + r"socket\b"]),
    "exec":        ("warn",   [r"\bsub" + r"process\.", r"\bos\.system\b", r"\bos\.popen\b",
                               r"\beval\s*\(", r"\bexec\s*\(", r"\bcompile\s*\(", r"\b__import__\s*\(",
                               r"child_" + r"process", r"\.exec" + r"Sync\b",
                               r"Function\s*\(\s*['\"]", r"Runtime\.getRuntime"]),
    "deserialize": ("warn",   [r"\bpickle\.(?:load|loads)\b", r"\byaml\.load\s*\((?![^)]*Loader)", r"\bmarshal\.loads\b"]),
    "secrets":     ("review", [r"os\.envi" + r"ron", r"process\.e" + r"nv", r"(?<![\w/])" + _SSH + r"\b",
                               r"(?<![\w/])" + _ENV + r"\b", _RSA + r"|" + _ED,
                               r"(?:api[_-]?key|secret|password|access[_-]?token)\s*[:=]",
                               r"AKIA[0-9A-Z]{16}", r"BEGIN [A-Z ]*PRIVATE KEY",
                               r"gh[pousr]_[A-Za-z0-9]{20,}", r"sk-[A-Za-z0-9]{20,}"]),
    "destructive": ("warn",   [r"shutil\.rm" + r"tree", r"os\.remove\s*\(", r"os\.unlink\s*\(",
                               r"\brm\s+-rf\b", _REMOVE_ITEM + r"[^\n]*-Recurse", r"fs\.rm(?:Sync)?\s*\(",
                               r"\bun" + r"link\s*\("]),
    "remote_exec": ("critical", [r"pip\s+install[^\n]*https?://", r"npm\s+install[^\n]*https?://",
                               r"curl[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash)", r"wget[^\n|]*\|\s*(?:sh|bash)",
                               r"Invoke-" + r"Expression", r"download" + r"String", r"Download" + r"File"]),
    "traversal":   ("review", [r"\.\./\.\./\.\."]),
}

def read(p):
    try: return p.read_text(encoding="utf-8", errors="replace")
    except Exception: return ""

def line_of(text, idx): return text.count("\n", 0, idx) + 1

def iter_files(skill_dir, exclude=()):
    for p in skill_dir.rglob("*"):
        if not p.is_file() or (set(p.parts) & SKIP_PARTS):
            continue
        if any(fnmatch.fnmatch(p.name, g) for g in exclude):
            continue
        yield p

def snippet(text, start, n=70):
    line = text[start:start + n].splitlines()
    return (line[0] if line else "").strip()

def audit_skill(skill_dir, scan_scripts=True, exclude=()):
    findings, n_scripts = [], 0
    for p in iter_files(skill_dir, exclude):
        ext = p.suffix.lower()
        t = read(p)
        for sev, label in scan_invisible(t):
            findings.append((sev, "invisible-unicode", p.name, "-", label))
        if ext in TEXT_EXTS:
            low = t.lower()
            for pat, sev, label in INJECTION:
                for m in re.finditer(pat, low):
                    findings.append((sev, "injection", p.name, line_of(t, m.start()),
                                     "%s: ...%s..." % (label, snippet(t, max(0, m.start()-15), 60))))
        elif ext in SCRIPT_EXTS:
            n_scripts += 1
            if scan_scripts:
                for pat, sev, label in INJECTION:
                    for m in re.finditer(pat, t.lower()):
                        findings.append((sev, "injection", p.name, line_of(t, m.start()), label))
                for cat, (sev, pats) in CODE.items():
                    for pat in pats:
                        for m in re.finditer(pat, t):
                            findings.append((sev, cat, p.name, line_of(t, m.start()), snippet(t, m.start())))
    seen, uniq = set(), []
    for f in findings:
        k = (f[1], f[2], f[3], f[4])
        if k not in seen:
            seen.add(k); uniq.append(f)
    return {"skill": skill_dir.name, "path": str(skill_dir),
            "n_scripts": n_scripts, "findings": uniq}

def find_skill_dirs(roots):
    dirs = set()
    for r in roots:
        rp = Path(r)
        if (rp / "SKILL.md").exists():
            dirs.add(rp)
        for s in rp.rglob("SKILL.md"):
            if not (set(s.parts) & SKIP_PARTS):
                dirs.add(s.parent)
    by_name = {}
    for d in sorted(dirs, key=lambda x: len(str(x))):
        by_name.setdefault(d.name, d)
    return sorted(by_name.values(), key=lambda x: str(x))

# --- C. baseline + drift ---------------------------------------------------
def fingerprint(skill_dir):
    files = {}
    for p in sorted(iter_files(skill_dir)):
        h = hashlib.sha256(p.read_bytes()).hexdigest()
        files[str(p.relative_to(skill_dir)).replace("\\", "/")] = h
    return files

def cmd_baseline(roots, out):
    data = {"version": 1, "skills": {}}
    for d in find_skill_dirs(roots):
        data["skills"][d.name] = {"path": str(d), "files": fingerprint(d)}
    Path(out).write_text(json.dumps(data, indent=2), encoding="utf-8")
    print("baseline: fingerprinted %d skills -> %s" % (len(data["skills"]), out))
    return 0

def cmd_drift(roots, baseline, as_json):
    base = json.loads(Path(baseline).read_text(encoding="utf-8"))
    report, any_change = [], False
    cur = {d.name: d for d in find_skill_dirs(roots)}
    for name, rec in base.get("skills", {}).items():
        if name not in cur:
            report.append((name, "REMOVED", [])); any_change = True; continue
        now, old = fingerprint(cur[name]), rec["files"]
        added   = sorted(set(now) - set(old))
        removed = sorted(set(old) - set(now))
        changed = sorted(f for f in set(now) & set(old) if now[f] != old[f])
        if added or removed or changed:
            any_change = True
            report.append((name, "CHANGED",
                           [("+ added", a) for a in added] +
                           [("- removed", r) for r in removed] +
                           [("~ modified", c) for c in changed]))
    for name in cur:
        if name not in base.get("skills", {}):
            report.append((name, "NEW (unvetted)", [])); any_change = True
    if as_json:
        print(json.dumps(report, indent=2)); return 1 if any_change else 0
    print("\n%s\n  DRIFT vs %s\n%s" % ("="*64, baseline, "="*64))
    if not any_change:
        print("  No drift. Every vetted skill is byte-identical to its baseline.\n")
        return 0
    for name, status, changes in report:
        print("\n  [%s] %s" % (status, name))
        for tag, f in changes:
            print("      %s: %s" % (tag, f))
    print("\n  ! %d skill(s) changed since vetting. Re-audit before trusting them -"
          "\n    an update can swap safe for malicious.\n" % len(report))
    return 1

def cmd_scan(roots, quiet, as_json, scan_scripts, exclude):
    results = [audit_skill(d, scan_scripts, exclude) for d in find_skill_dirs(roots)]
    if as_json:
        print(json.dumps(results, indent=2))
        return 1 if any(r["findings"] for r in results) else 0
    total = sum(len(r["findings"]) for r in results)
    flagged = [r for r in results if r["findings"]]
    n_scripts = sum(r["n_scripts"] for r in results)
    print("\n%s\n  SKILL-GUARD - %d skills, %d scripts scanned\n%s"
          % ("="*72, len(results), n_scripts, "="*72))
    for r in sorted(results, key=lambda r: -len(r["findings"])):
        if not r["findings"]:
            if not quiet:
                print("  [CLEAN]   %s  (%d scripts)" % (r["skill"], r["n_scripts"]))
            continue
        fs = sorted(r["findings"], key=lambda f: RANK.get(f[0], 9))
        print("\n  [FLAGGED] %s  (%d scripts - %d candidates)" % (r["skill"], r["n_scripts"], len(fs)))
        for sev, cat, fn, ln, detail in fs[:30]:
            print("      %-8s %-17s %s:%s  %s" % (sev.upper(), cat, fn, ln, str(detail)[:64]))
        if len(fs) > 30:
            print("      ... +%d more" % (len(fs)-30))
    print("\n%s" % ("-"*72))
    print("  Skills flagged: %d/%d   candidates: %d" % (len(flagged), len(results), total))
    print("  Candidates are QUESTIONS, not verdicts. For each: does the skill's stated")
    print("  purpose justify it?  Escalate anything ambiguous to an independent")
    print("  adversarial agent, and read the raw text yourself (see SKILL.md).\n")
    return 1 if total else 0

def main():
    ap = argparse.ArgumentParser(prog="skill_guard.py", description="Static security auditor for AI agent skills.")
    sub = ap.add_subparsers(dest="cmd")
    s = sub.add_parser("scan", help="audit skills for risky content")
    s.add_argument("dirs", nargs="+"); s.add_argument("--quiet", action="store_true")
    s.add_argument("--json", action="store_true"); s.add_argument("--no-scripts", action="store_true")
    s.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="filename glob to skip (repeatable), e.g. --exclude 'test_*'")
    b = sub.add_parser("baseline", help="record fingerprints of vetted skills")
    b.add_argument("dirs", nargs="+"); b.add_argument("--out", required=True)
    d = sub.add_parser("drift", help="detect changes since a baseline")
    d.add_argument("dirs", nargs="+"); d.add_argument("--baseline", required=True)
    d.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if a.cmd == "scan":
        sys.exit(cmd_scan(a.dirs, a.quiet, a.json, not a.no_scripts, a.exclude))
    elif a.cmd == "baseline":
        sys.exit(cmd_baseline(a.dirs, a.out))
    elif a.cmd == "drift":
        sys.exit(cmd_drift(a.dirs, a.baseline, a.json))
    else:
        ap.print_help(); sys.exit(2)

if __name__ == "__main__":
    main()
