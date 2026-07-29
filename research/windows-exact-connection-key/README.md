# Windows exact connection-key research

This directory contains the reproducible evidence for the Windows
`connection_hash_table` source-port collision reported in upstream issue #209.

## Scope

The confirmed legacy defect allows distinct flows to collide when they reuse
the same numeric local source port. The candidate key is:

```text
transport protocol
+ address family
+ original local source address
+ local source port
```

The evidence is grouped into:

- `runtime-reproduction/` — deterministic old-build collision and control data;
- `design/` — key design and #206 decision-state reconciliation;
- `correctness/` — unit/build and targeted TCP/UDP packet-path probes;
- `performance/external-web/` — contextual browser/network measurements;
- `performance/fixed-endpoint/` — primary old-vs-candidate performance gate;
- `release/` — complete candidate diff, manifest, canary smoke and final report;
- `issue/` — prepared upstream issue update.

## Primary results

- old-build deterministic TCP/UDP collision: confirmed;
- exact table and decision tests: 41/41;
- repeated tests: 10/10 runs, 410 test invocations;
- TCP endpoint orientation: 5/5;
- UDP pktinfo orientation: 6/6;
- exact TCP packet-path probe: 9/9;
- canary smoke: pass;
- fixed endpoint: 120/120 requests per build, zero failures;
- normalized performance difference: candidate +0.373%;
- performance verdict: `PRACTICALLY_EQUIVALENT`.

## Limitation

The exact old-build collision is confirmed end-to-end. The candidate has passed
unit, packet-path, canary and performance validation, but the same deterministic
collision has not yet been rerun through the complete real-WinDivert candidate
runtime.
