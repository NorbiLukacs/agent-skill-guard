# Sample audit — what a real run looks like

Running Skill Guard's scanner across an installed plugin tree:

```
$ python skill_guard.py scan ~/.claude/plugins/cache --quiet

========================================================================
  SKILL-GUARD - 83 skills, 41 scripts scanned
========================================================================

  [FLAGGED] brainstorming  (4 scripts - 25 candidates)
      REVIEW   secrets           server.cjs:113  process.env.BRAINSTORM_OWNER_PID)
      WARN     exec              server.cjs:539  child_process (opens browser)
      ...
  [FLAGGED] skill-creator  (10 scripts - 10 candidates)
      WARN     exec              run_eval.py:85  subprocess.Popen(
      ...
  [FLAGGED] writing-skills  (1 scripts - 2 candidates)
      WARN     exec              render-graphs.js:18  child_process

------------------------------------------------------------------------
  Skills flagged: 3/83   candidates: 37
```

## How to read this

None of the three flagged skills is malicious — and that's the point of the
**triage** step. Each candidate is a *question*:

| Skill | Capability flagged | Does its purpose justify it? |
|-------|-------------------|------------------------------|
| `brainstorming` | `process.env`, `child_process` | Yes — it runs a local browser-companion server. |
| `skill-creator` | `subprocess` | Yes — it runs skill evals. |
| `writing-skills` | `child_process` | Yes — it renders Graphviz diagrams. |

All three resolve at triage. Nothing reaches the adversarial-agent step.

Compare this to the **first, untuned** version of the scanner on the same tree:
**72 candidates, all false positives** — legitimate `curl` in documentation, the
phrase "use when asked", a security skill discussing "data exfiltration". Tuning
the patterns to demand *imperative + target* (not topic mentions) cut the noise
by ~half while keeping every real capability visible.

## The lesson

A scanner that cries wolf trains you to ignore it. Skill Guard reports
**candidates for human judgment**, never verdicts — and pairs the scan with an
independent adversarial agent for anything that can't be resolved by purpose
alone. See [`SKILL.md`](../skills/skill-guard/SKILL.md) for the full funnel.
