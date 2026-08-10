# RustyAuth 1.0.0 Starter single-realm baseline

Status: **passed**\
Run: `starter-20260810T145154Z`\
Observed: 10 August 2026, 14:52:10–15:06:24 UTC

## Result

A template-derived Railway realm with a 1 vCPU / 512 MB RustyAuth API and a 1 vCPU / 1 GB SableDB served every
configured authenticated-read tier through 800 requests/second. The breakpoint was not reached, so this report
establishes a conservative lower bound of **at least 800 authenticated RPS**; it does not claim that 800 RPS
is the realm's absolute ceiling.

The run completed 141,764 authenticated reads and 31 full synthetic passkey sign-ins with zero request
failures, zero unplanned 5xx responses and zero dropped iterations. At 800 RPS, authenticated reads measured
76.456 ms p95 and 130.793 ms p99. Passkey sign-in measured 118 ms p95 and 129.1 ms p99.

Applying the published 30% throughput reserve gives 5,600 supported simultaneously active users for the
typical six-requests-per-minute profile. This is active workload capacity, not the number of accounts or idle
sessions: the measured realm contained 10,000 registered accounts and 10,000 valid sessions.

## Resource and continuity review

The API peaked at 0.140 vCPU and 36.6 MB of its 1 vCPU / 512 MB limit. SableDB peaked at 0.384 vCPU and 133.7
MB of its 1 vCPU / 1 GB limit. The API, dashboard and SableDB remained on their pinned successful deployments
throughout the run; no application errors, listener restarts, readiness loss or deployment changes were
observed. API and dashboard readiness probes remained healthy after completion.

## Reproduction boundary

The runtime artifacts were built from `6a73d1ce366032ac13e65da45e5c8abecabcb1f4`; the runner containing the
expired-session recovery fix was built from `8007503d64c9e2d6241e1da55f4b81039148f66a`. All deployed API,
dashboard and SableDB artifacts are recorded by immutable SHA-256 digest in `reviewed-evidence.json` and the
public benchmark catalogue.

`raw-k6-summaries.json` retains the unmodified parsed k6 summary exports. `source-SHA256SUMS` records the
hashes generated inside the isolated runner before review. Fixture private keys and session tokens are
intentionally excluded.
