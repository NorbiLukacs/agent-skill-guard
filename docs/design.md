# Skill Guard — design notes

## Problem

AI agent "skills" (Claude Code skills, plugins, MCP servers) are instructions and
bundled code that run with the agent's full permissions. Installing one from a
registry like skills.sh is a supply-chain trust decision. Existing vetting skills
(e.g. `skill-vetter`, 20K installs) are valuable but are **pure-markdown
methodologies**: an LLM reads the skill and judges it. That leaves three
structural gaps.

## The three structural gaps (and our answers)

| # | Gap | Why an LLM-only review can't close it | Answer |
|---|-----|----------------------------------------|--------|
| A | Invisible Unicode | Zero-width / bidi / Tag-block chars fragment or vanish in tokenization; the model can't reliably "see" them | Deterministic **byte-level** scan |
| B | Reviewer is in range | Reading a hostile skill into your own context is what a subversion payload targets | **Independent adversarial sub-agent**, never told the expected answer |
| C | Time-of-check ≠ time-of-use | A vetted skill can be swapped by a later update | **Fingerprint + drift** diff |

Plus **D**: code-level analysis of bundled scripts (network / exec / secrets /
destructive / remote-install / traversal).

## Architecture

- **`scripts/skill_guard.py`** — stdlib-only scanner. Three subcommands:
  `scan` (audit), `baseline` (record sha256 fingerprints), `drift` (diff vs
  baseline). No network, no child processes, read-only except `baseline`'s output
  file. Source is pure-ASCII (hidden-char signatures built with `chr()`, code
  signatures split with `+`) so the tool passes its own audit.
- **`skills/skill-guard/SKILL.md`** — the methodology. Teaches the agent the
  funnel: scan → purpose-aware triage → adversarial agent (B) → show the human raw
  text → record a baseline (C).
- **`scripts/test_skill_guard.py`** — builds throwaway skills with known attacks
  and asserts detection + no false positives + drift.

## Key decision: candidates, not verdicts

The first untuned scanner produced 72 candidates / 0 real on 83 skills. A tool
that cries wolf is worse than none. So: patterns demand *imperative + target*
(not topic mentions), `curl`-in-docs ≠ `curl | sh`, and every flag is explicitly
a **question for human/agent triage**, never an automated "MALICIOUS".

## Explicitly out of scope (YAGNI)

No auto-install, no auto-quarantine/delete, no CI service, no telemetry, no
runtime sandboxing. Skill Guard reports; humans decide.

## Relationship to `skill-vetter`

Complementary, not a clone. `skill-vetter` does broad markdown-level vetting
(permissions, typosquatting, metadata). Skill Guard adds the three things a
markdown reader structurally cannot do (A, B, C) and deeper code analysis (D). Use
both; they overlap on the easy cases and diverge exactly where it matters.
