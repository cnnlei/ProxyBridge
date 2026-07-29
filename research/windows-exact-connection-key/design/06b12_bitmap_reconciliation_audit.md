# 6B.12A — bitmap reconciliation audit

## Source identity

- Workspace: `D:\ProxyBridge-Lab\ConnHash-Fix`.
- Audited file: `Windows\src\ProxyBridge.c`.
- SHA-256: `4C5EF72F33C9144EB1FE7033D299DEC900EB32FFD75DCA37186A7DC0ABA29825` — matched preflight.
- Audit mode: read-only; no build, test, runtime, deployment, or Git operation was performed.
- Exact key currently is `protocol + family + original local source address + source port`.
- Bitmap state notation below: `0=(decided=0,direct=0)`, `D=(1,1)`, `N=(1,0)`; `N` cannot distinguish PROXY from BLOCK.

## Complete bitmap call-site inventory

All executable helper calls are in outbound TCP handling. The bitmap gate runs before the code distinguishes a normal outbound packet from an outbound-captured relay response (`source port == g_local_relay_port`). No UDP path calls any bitmap helper.

| Line | Operation | Family/path | Packet state | Relative to exact lookup | Early `continue` possible |
|---:|---|---|---|---|---|
| 1446 | `port_clear(sp)` | IPv6 TCP outbound, before relay split | fresh SYN | before bitmap/exact | no |
| 1448 | `port_is_decided(sp)` | IPv6 TCP outbound, including relay response | non-fresh established/SYN-ACK/FIN-RST | before exact | not alone; enables line 1451 |
| 1450 | `port_clear(sp)` | same | decided FIN/RST | before exact | no |
| 1451 | `port_is_direct(sp)` | same | non-fresh; FIN/RST has just cleared the bit | before exact | yes: unchanged send + `continue` |
| 1513 | `port_clear(sp)` | IPv6 normal outbound, tracked PROXY hit | FIN/RST | after exact `touch_tracked` | no; redirect follows |
| 1610 | `port_set_direct(sp)` | IPv6 normal outbound DIRECT | fresh SYN or shortcut miss | after rule + exact upsert | yes: unchanged send |
| 1616 | `port_set_decided(sp)` | IPv6 normal outbound BLOCK | fresh SYN or shortcut miss | after rule + exact upsert | yes: drop |
| 1621 | `port_set_decided(sp)` | IPv6 normal outbound PROXY | fresh SYN or shortcut miss | after rule + exact upsert | route rewrite + send |
| 1957 | `port_clear(src_port)` | IPv4 TCP outbound, before relay split | fresh SYN | after PID-cache eviction; before bitmap/exact | no |
| 1960 | `port_is_decided(src_port)` | IPv4 TCP outbound, including relay response | non-fresh established/SYN-ACK/FIN-RST | before exact | not alone; enables line 1964 |
| 1963 | `port_clear(src_port)` | same | decided FIN/RST | before exact | no |
| 1964 | `port_is_direct(src_port)` | same | non-fresh; FIN/RST has just cleared the bit | before exact | yes: unchanged send + `continue` |
| 2023 | `port_clear(src_port)` | IPv4 normal outbound, tracked PROXY hit | FIN/RST | after exact `touch_tracked` | no; redirect follows |
| 2119 | `port_set_direct(src_port)` | IPv4 normal outbound DIRECT | fresh SYN or shortcut miss | after rule + exact upsert | yes: unchanged send |
| 2126 | `port_set_decided(src_port)` | IPv4 normal outbound BLOCK | fresh SYN or shortcut miss | after rule + exact upsert | yes: drop |
| 2135 | `port_set_decided(src_port)` | IPv4 normal outbound PROXY | fresh SYN or shortcut miss | after rule + exact upsert | route rewrite + send |

Definitions at lines 233–237 prove that `port_clear` clears both `decided` and `direct`. Stop resets both complete arrays at lines 6618–6619. There is no bitmap TTL or periodic bitmap cleanup.

## Fresh-SYN reconciliation with #206

Normal IPv4 fresh SYN order is:

1. Compute `fresh_syn = Syn && !Ack`; build exact key and capture destination before mutation.
2. Remove the exact IPv4 PID-cache entry (`remove_cached_pid(src_ip, src_port, FALSE)`).
3. Clear both bitmap bits.
4. Skip the `!fresh_syn && port_is_decided` fast path.
5. Skip the `!fresh_syn && connection_table_touch_tracked` shortcut.
6. Run process/rule lookup and policy overrides.
7. Exact upsert for every action; `tracked=TRUE` only for PROXY.
8. Set `D` for DIRECT or `N` for PROXY/BLOCK; then send unchanged, redirect, or drop.

IPv6 has the same order except that there is no IPv6 PID cache to evict: `port_clear` is followed by both fresh-SYN bypasses, rule lookup, exact upsert, bitmap decision, and action.

This implements the minimum #206 meaning recorded in the integration contract: an observed fresh SYN cannot consume a stale bitmap or tracked-table decision and must replace exact metadata before action. A cherry-pick is not indicated: the semantic overlap is already present. It does **not** reconcile simultaneous endpoints after their SYNs or any flow whose fresh SYN was not observed.

## Simultaneous endpoint truth table

The rows assume the stated SYN order, then the next non-terminal non-SYN packet of flow 1 followed by flow 2. Reversing packet order can delay, but does not remove, the unsafe transition in A/C.

| Case | After SYN 1 | After SYN 2 | Next packet of flow 1 | Next packet of flow 2 | Result |
|---|---|---|---|---|---|
| A. IPv4 DIRECT A:P; IPv6 PROXY B:P | `D` | `N` | exact touch is FALSE → rule/upsert DIRECT → sets `D`, sends | sees `D` → `FAST_DIRECT`, no exact lookup | PROXY is wrongly sent DIRECT |
| B. IPv6 PROXY B:P; IPv4 DIRECT A:P | `N` | `D` | sees `D` → `FAST_DIRECT`, no exact lookup | sees `D` → correct DIRECT | PROXY is wrongly sent DIRECT immediately |
| C. IPv4 DIRECT A:P; IPv4 PROXY B:P, A≠B | `D` | `N` | exact touch FALSE → rule/upsert DIRECT → sets `D` | sees `D` → `FAST_DIRECT`, no exact lookup | same-family/address collision causes wrong routing |
| D. IPv4 BLOCK A:P; IPv6 DIRECT B:P | `N` | `D` | sees `D` → unchanged send, no exact lookup | sees `D` → correct DIRECT | BLOCK packet is wrongly allowed |
| E. Two DIRECT flows at P | `D` | `D` | `FAST_DIRECT`, no exact lookup | `FAST_DIRECT`, no exact lookup | routing correct for these two actions |
| F. Two PROXY flows at P | `N` | `N` | exact tracked hit → correct redirect | exact tracked hit → correct redirect | routing correct; exact keys remain distinct |

Thus FAST_DIRECT can affect both PROXY and BLOCK flows. A/C first incur an extra rule lookup for the DIRECT flow, then become a wrong-routing case; the defect cannot be classified as performance-only. The pre-relay bitmap gate can also bypass relay-response reconstruction if a shared/stale `D` exists for `g_local_relay_port`.

## FIN/RST behavior

| Existing action | Bits before | Immediately after first `port_clear` | Following path | Bits after packet | Exact entry |
|---|---|---|---|---|---|
| DIRECT | `D` | `0`; the subsequent `port_is_direct` sees cleared state | exact tracked touch FALSE → rule → upsert → DIRECT send | re-armed to `D` | retained |
| PROXY | `N` | `0` | exact tracked touch TRUE; second clear; redirect | remains `0` | retained and touched |
| BLOCK | `N` | `0` | exact tracked touch FALSE → rule → upsert → drop | re-armed to `N` | retained |

Production has zero `connection_table_remove` calls. A following observed fresh SYN clears any re-armed bitmap and overwrites the exact entry, so #206 still protects that boundary. Without an observed SYN, terminal re-arm leaves a correctness risk for DIRECT and a performance/staleness issue for BLOCK; exact entries remain until periodic cleanup. Clearing before `port_is_direct` does prevent a terminal PROXY/BLOCK packet itself from taking stale FAST_DIRECT.

## Mid-flow/startup behavior

- At a clean start both bitmaps and the new exact table are empty. A first observed ACK with a parsed TCP header misses both shortcuts, runs rules, and upserts; it is not misrouted solely because startup missed its SYN.
- If another endpoint with the same P establishes `D` first, a later first-observed ACK for a PROXY/BLOCK endpoint takes wrong FAST_DIRECT before exact lookup.
- With shared `N`, an exact-key miss reaches rules; that is initially correct, but a DIRECT result sets shared `D` and can then misroute the other endpoint.
- A lost FIN/RST or DIRECT terminal re-arm can leave `D` indefinitely until fresh SYN or Stop; exact-table TTL cleanup does not clear the bitmap.
- A fragment for which parsing yields no TCP header does not call the bitmaps. Current IPv6 code forwards it unchanged; current IPv4 code takes its existing `continue` path. A first fragment containing a parsed TCP header follows the ACK analysis above.

## Design alternatives

| Alternative | Correctness / remaining collisions | Hot path | Lifecycle and concurrency | Source/test work |
|---|---|---|---|---|
| A. Keep current bitmaps | incorrect: cross-family, cross-address, missed-SYN, stale-terminal, and pre-relay DIRECT collisions remain | fastest DIRECT path | separate non-TTL state can diverge from exact table; atomic writes do not fix key aliasing | none, but unacceptable |
| B. One bitmap pair per family | fixes A/B/D only; same-family different-address case C and temporal/pre-relay collisions remain | still very cheap; doubles bitmap storage | same independent lifecycle and logical races | small `ProxyBridge.c` change plus packet tests; still insufficient |
| C. Exact-key decision in current connection table | correct for the defined endpoint key and all A–F; temporal reuse must be invalidated on terminal/fresh SYN | one hash + shared-lock lookup; avoids process/rule lookup for all three actions | reuse table lock, TTL, cleanup, ownership, and Stop join; no second cache to reconcile | moderate core/header/call-site/unit-test change |
| D. Remove bitmap fast path; keep current exact tracked/rule path | correct for A–F; DIRECT/BLOCK run rules on every packet | potentially severe kernel/PID/rule cost on DIRECT and BLOCK traffic | simplest lifecycle; exact table remains authoritative only for PROXY | small `ProxyBridge.c` change and packet tests |

Adding a typed decision to the existing table entry is safe and preferable to a separate decision cache. Extending `CONNECTION_SNAPSHOT` is technically safe because it is a value copy, but using the full routing snapshot on every packet is unnecessary. A dedicated decision lookup keeps routing reconstruction separate while sharing the same exact entry and lock.

Minimum key remains the existing `CONNECTION_KEY`: protocol, family, local address, and local port. Destination, PID, and proxy config are values or rule inputs, not needed for the collision classes audited here and should not be added in this stage.

## Verdict

**SOURCE_CHANGE_REQUIRED**

Minimum recommended design:

- Add `CONNECTION_DECISION_NONE/DIRECT/PROXY/BLOCK` to `connection_table.h` and store it atomically with each upserted value.
- Change `connection_table_upsert(..., BOOL is_tracked, ...)` to accept the typed decision instead; derive existing tracked semantics from `decision == PROXY` so UDP behavior remains unchanged.
- Add `connection_table_touch_decision(table, key, now, decision_out)` for the TCP hot path.
- Add `connection_table_clear_decision(table, key)` for FIN/RST; it must preserve destination/config metadata needed by relay reconstruction.
- In both TCP families, handle `source port == g_local_relay_port` before any normal-flow decision shortcut.
- Fresh SYN continues to bypass lookup, run rules, and atomically overwrite decision plus routing value. Non-fresh hit applies DIRECT/PROXY/BLOCK without rule lookup; terminal processing clears only decision validity after selecting the action.
- Remove the two port-only arrays/helpers and their packet/Stop uses after the exact decision path is complete.

Production files for the next edit: `Windows/src/ProxyBridge.c`, `Windows/src/connection_table.h`, and `Windows/src/connection_table.c`. Unit-test file: `Windows/tests/connection_table_tests.c`. No `compile.ps1` or runner change is required.

Minimum unit tests: three-action round-trip/update; same P separated by family; same family/P separated by local address; decision miss; fresh overwrite; decision clear preserving `get_full`; tracked compatibility for UDP PROXY; cleanup/destroy; concurrent touch/clear safety.

Out of scope: UDP packet/relay behavior, destination/PID/config in the key, SOCKS5 framing, relay reconstruction algorithms, cleanup interval, startup/join ownership, WinDivert settings, profiles, deployment, and unrelated warnings.

## Next minimal tests

1. Core unit tests listed above, including repeated touch/clear concurrency runs within the existing testing policy.
2. A source gate proving zero production bitmap references and relay-response reconstruction precedes decision lookup.
3. Targeted packet/runtime cases A–F with distinct IPv4/IPv6/local-address endpoints and action assertions.
4. DIRECT, PROXY, and BLOCK FIN/RST cases: action is applied once, decision becomes NONE, routing snapshot remains where required, and a following fresh SYN installs the new action.
5. Mid-flow ACK with another endpoint already holding the same P; plus a relay-response case proving no decision shortcut can bypass reconstruction.

## Runtime GO/NO-GO

**NO-GO** for general candidate runtime testing in the current source state. Cases A–D contain reachable wrong-routing paths before exact lookup. Proceed to runtime only after the exact-key decision change passes the minimal unit/source gates; then use the targeted cases above.
