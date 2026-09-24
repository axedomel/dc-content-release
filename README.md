# DC Content — NetWitness Detection Content Pack

A ready-to-deploy NetWitness Application Rule detection content pack: 301
custom App Rules plus a 16-rule LLM/AI usage detection add-on, covering
network-session-based detection across recon, lateral movement, C2,
exfiltration, cloud credential abuse, phishing, and shadow-AI/LLM usage.

## What's in here

| Path | What it is |
|---|---|
| `rules/` | Every rule as its own single-rule `.nwr` file — import individually, or pick a subset. 317 files (301 core + 16 LLM pack). |
| `DC_Content_All_Rules_1_of_2_AR1-AR151.nwr` | Core pack, rules AR1–AR151, as one multi-rule import file. |
| `DC_Content_All_Rules_2_of_2_AR152-AR301.nwr` | Core pack, rules AR152–AR301, as one multi-rule import file. |
| `DC_Content_llm_pack_v0.9.nwr` | The 16-rule LLM/AI usage detection add-on, as one multi-rule import file. |
| `DC_Content_Rule_Catalog.xlsx` | Full catalog: every rule's AR ID, name, MITRE ATT&CK tactic/technique, alert type (BOC/IOC/EOC), the exact NWQL condition, and a plain-English description of what it detects. |
| `feeds/` | The custom feed a handful of LLM-pack rules depend on (see below) — without it, those specific rules deploy but silently never fire. |
| `dist/` | Versioned release zips — the whole pack, one download. |

## Why two files for the core pack

NetWitness's App Rule import caps a single multi-rule `.nwr` file at 300
rules. The core pack is 301 rules, so it's split across two files —
import both, they don't overlap.

## Alert types

- **IOC** — Indicator of Compromise: a known-bad artifact or pattern matched directly.
- **BOC** — Behavior of Compromise: an observed action consistent with malicious activity.
- **EOC** — Enabler of Compromise: a weakness or exposure that increases risk but isn't itself an active-attack signal.

## The `_feed_`-marked LLM pack rules

A handful of the LLM pack's rules (filename contains `_feed_`) match against
`threat.category` values that only get populated once the feed in `feeds/`
is loaded into your NetWitness deployment. Deploy the feed first, or those
specific rules will sit there with zero hits.

## Importing

Use NetWitness's own App Rule import (Decoder/Log Decoder → Config →
App Rules → import), pointing at either the individual `rules/*.nwr`
files or the consolidated multi-rule files above.
