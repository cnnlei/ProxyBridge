## Candidate fix, source branch, and full validation results

I completed a candidate implementation and a broader validation pass for the Windows source-port-only connection tracking defect described in this issue.

### Source branch

Candidate source and reproducible research artifacts:

- Branch: https://github.com/dentatli/ProxyBridge/tree/fix/windows-exact-connection-key
- Evidence index: https://github.com/dentatli/ProxyBridge/tree/fix/windows-exact-connection-key/research/windows-exact-connection-key

The branch is based on:

```text
1f18417c4075167d595a95e4ce9e3999e5dc8d6d
```

Candidate DLL SHA-256:

```text
CC6A53988D6ECF2CD175D00CC8DBD0C4E29D21B0480AA9248E60202C8090BA83
```

### Fix implemented

The legacy Windows tracking table effectively used the numeric local source port as connection identity. The candidate replaces that with:

```text
transport protocol
+ address family
+ original local source address
+ local source port
```

The old port-only decision bitmaps were also replaced with exact-key decision state. This prevents a stale or unrelated DIRECT / PROXY / BLOCK decision from bypassing exact rule evaluation when the same numeric port is reused by another protocol, address family, or local address.

Destination and proxy metadata remain values rather than key fields. This is an intentional near-term relay-correlation design. A full destination-aware 5-tuple table would require a separate pending-relay index and a larger UDP session redesign.

### Deterministic old-build reproduction

The original runtime reproduction used:

```text
UDP 192.168.0.136:55123 -> 193.124.56.249:41001
TCP 192.168.0.136:55123 -> 193.124.56.249:41002
```

The fresh TCP SYN was incorrectly matched to the existing UDP entry:

```text
request_protocol=TCP
matched_protocol=UDP
protocol_collision=1
destination_collision=1
actual_path=TRACKED_REDIRECT
rule_lookup_called=0
```

The UDP request succeeded, while the TCP connection timed out.

### Validation completed

Correctness and build gates:

- exact connection-table and decision-state tests: **41/41 passed**
- repeated test runs: **10/10**, 410 total test invocations
- TCP accepted-socket endpoint-orientation probe: **5/5 passed**
- UDP `WSARecvMsg` + `IP_PKTINFO` / `IPV6_PKTINFO` probe: **6/6 passed**
- exact TCP decision packet-path probe: **9/9 passed**
- candidate DLL build: passed
- export gate: **19 expected exports**, none missing or unexpected
- DIRECT TCP smoke: passed
- PROXY TCP smoke: passed
- BLOCK TCP smoke: passed
- UDP smoke: passed
- three start/stop cycles: passed
- no crash, hang, or unexpected timeout

The packet-path probe covered cross-protocol, IPv4/IPv6, multiple-local-address, BLOCK/DIRECT, dual-DIRECT, dual-PROXY, terminal-clear, mid-flow ACK, and relay-response-ordering cases.

### Fixed-endpoint old-vs-candidate performance test

I compared the old and candidate DLLs against one deterministic HTTP endpoint on the same VPS.

The test removed DNS, TLS, CDN selection, browser cache, and changing third-party content. It used 1 KiB, 64 KiB, 1 MiB, and 8 MiB responses, with 30 measured requests per size per build.

```text
old:       120/120 successful requests
candidate: 120/120 successful requests
failures:  0
```

Normalized result across the four response sizes:

```text
candidate mean per-size total-time improvement: +0.373%
verdict: PRACTICALLY_EQUIVALENT
```

Per-size trimmed-mean total-time changes:

```text
1 KiB:  -1.189%
64 KiB: +2.835%
1 MiB:  -0.833%
8 MiB:  +0.680%
```

All 95% bootstrap confidence intervals included zero. Individual total-time outcomes were nearly balanced:

```text
candidate / old / tie = 56 / 55 / 9
```

No CPU, memory, or handle regression was detected.

### Real-world canary experience

I have also been using the candidate build as a real desktop canary rather than only running synthetic tests.

Observed working scenarios include:

- normal browser traffic through SOCKS5;
- Discord text/media loading;
- Discord voice traffic;
- viewing Discord streams;
- UDP relay operation and reconnects;
- repeated application start/stop cycles.

Discord voice latency did not become worse, stream viewing remained stable, and I did not observe new hangs, crashes, or unexplained connection failures.

For browser use, I moved the browser itself into ProxyBridge rules instead of sending selected browser domains through the SmartProxy extension. Subjectively, page and media loading felt at least as good and often better through ProxyBridge. A controlled SmartProxy-equivalent benchmark did not prove a universal browser speed advantage, but it showed no regression and the ProxyBridge path had a better overall result in that sample. I am treating the subjective browser improvement as user experience, not as a formal performance claim.

### Separate domain-rule UI issue

During browser-rule migration I found a separate rule-editor/profile issue:

- the UI indicates semicolon-separated domain entries;
- the current native parser uses comma separation;
- the domain field is silently truncated at 255 characters after save/reopen.

That caused a long imported domain list to end in the middle of a hostname. I worked around it by splitting the list into several rules. I plan to report this separately because it is a GUI/profile serialization issue, not part of the connection-key defect.

### Current conclusion

```text
old-build defect reproduction:              confirmed
root cause:                                 confirmed
candidate implementation:                   complete
unit/build/targeted probes:                  passed
canary smoke and real-world use:             passed
normal-path performance regression:          not detected
fixed-endpoint performance:                  practically equivalent
```

One limitation remains: the exact UDP-seed/TCP-same-source-port scenario has been proven end-to-end on the old build, while the candidate has so far been validated by unit tests, actual packet-path probes, canary operation, and performance tests. I have not yet repeated that exact collision through the complete real-WinDivert candidate runtime. Therefore I am not presenting this as the final merged fix yet.

The branch and evidence are available for maintainer review. I can convert it into a PR after the implementation direction is accepted.
