# ProxyBridge Windows exact connection-key fix — итоговый отчёт валидации

Дата: 2026-07-29  
Базовый HEAD: `1f18417c4075167d595a95e4ce9e3999e5dc8d6d`  
Старая DLL: `1B702EC855838514424BA76188ADF98A1CCE079E94EC8D3BDDA8AD1ECCF0F749`  
Candidate DLL: `CC6A53988D6ECF2CD175D00CC8DBD0C4E29D21B0480AA9248E60202C8090BA83`

## 1. Итоговый вердикт

**GO для публикации результатов и candidate-дизайна в upstream issue.**

**GO для продолжения controlled canary.**

**HOLD для формулировки “полностью подтверждено в реальном collision runtime” и для merge/PR без оговорок**, потому что deterministic same-source-port collision был воспроизведён на старой версии, а candidate пока проверена unit/probe/canary/performance-набором, но не повторным end-to-end C1 через реальный WinDivert.

Основной performance gate закрыт:

- fixed endpoint: `PRACTICALLY_EQUIVALENT`;
- среднее нормализованное улучшение candidate по четырём размерам: **0.373%**;
- 120/120 запросов old и 120/120 candidate успешны;
- подтверждённой регрессии CPU, памяти или handles нет.

## 2. Подтверждённый дефект старой версии

Детерминированный runtime-сценарий:

1. UDP: `192.168.0.136:55123 -> 193.124.56.249:41001`;
2. затем TCP с тем же numeric source port:
   `192.168.0.136:55123 -> 193.124.56.249:41002`.

Старая таблица сопоставила новый TCP SYN с UDP-записью только по `55123`:

```text
request_protocol=TCP
matched_protocol=UDP
protocol_collision=1
destination_collision=1
actual_path=TRACKED_REDIRECT
rule_lookup_called=0
```

UDP seed прошёл, а TCP connect завершился `WSAETIMEDOUT (10060)` примерно через 10 секунд.

## 3. Реализованная модель

Новый relay-correlation key:

```text
protocol
+ address family
+ original local source address
+ source port
```

То есть:

```text
IPPROTO_TCP/IPPROTO_UDP
+ AF_INET/AF_INET6
+ original local IPv4/IPv6
+ source port
```

Destination и proxy configuration остаются значением записи, а не частью ключа. Это намеренный near-term дизайн, сохраняющий текущее UDP session behavior. Полный destination-aware 5-tuple остаётся отдельной будущей задачей.

Дополнительно старые `port_decided_bitmap` / `port_direct_bitmap` заменены exact-key decision state, чтобы bitmap fast path не обходил новую таблицу при IPv4/IPv6, local-address или action collisions.

## 4. Source/build integrity

Production candidate состоит из пяти файлов:

| Файл | SHA-256 |
|---|---|
| `Windows/compile.ps1` | `9B7125B8E6912224F3F68B1CD0547E1C2F77852B2F0A971BE91F3A9437CD21B6` |
| `Windows/src/connection_table.c` | `93AF004E0D40AF69757EA8FF4E2E6B0C062D41D5A565A07277F1591C9C0E7347` |
| `Windows/src/connection_table.h` | `DA649ECFA91AA9E2D6FB7715AAE2956DCE1F57AB0F96EF02DD033DD07983A222` |
| `Windows/src/ProxyBridge.c` | `C25A91D969ED93518F16D7B84364B60968170EC278F740BB4CC0BC2AE37E304D` |
| `Windows/tests/connection_table_tests.c` | `8A133635B53D243BF810274021F8495861318CCB77E282899A6BC73F0C4AF63C` |

Complete candidate diff:

```text
7E6398EB5A3774B8B381D6645AEFB01EF0B9C7C8795B13D3CFCE363B4FAF430C
```

Final candidate DLL:

```text
size: 93184 bytes
SHA-256: CC6A53988D6ECF2CD175D00CC8DBD0C4E29D21B0480AA9248E60202C8090BA83
exports: 19 expected, 0 missing, 0 unexpected
```

## 5. Correctness validation

| Gate | Результат |
|---|---|
| Connection-table and exact-decision unit tests | **41/41 PASS** |
| Repeated unit runs | **10/10 PASS**, 410 test invocations |
| TCP accepted-socket orientation | **5/5 PASS** |
| UDP WSARecvMsg + IP_PKTINFO/IPV6_PKTINFO | **6/6 PASS** |
| TCP exact-decision packet-path probe | **9/9 PASS** |
| Candidate application start | PASS |
| DIRECT TCP | PASS |
| PROXY TCP | PASS |
| BLOCK TCP | PASS |
| UDP traffic | PASS |
| Start/stop lifecycle | **3/3 PASS** |
| Crash, hang, unexpected timeout in smoke | none |

TCP packet-path probe covered:

- IPv4 DIRECT / IPv6 PROXY same numeric port;
- reverse IPv6 PROXY / IPv4 DIRECT;
- two local IPv4 addresses;
- BLOCK / DIRECT cross-family;
- dual DIRECT;
- dual PROXY;
- terminal decision clear;
- mid-flow ACK isolation;
- relay-response ordering.

## 6. Performance validation

### 6.1 Fixed endpoint old vs candidate — primary performance gate

Endpoint characteristics:

- one static VPS endpoint;
- no DNS;
- no TLS;
- no CDN selection;
- deterministic bodies;
- sizes: 1 KiB, 64 KiB, 1 MiB, 8 MiB;
- 30 measured requests per size per build;
- identical seed and request ordering;
- total: **240 measured requests**, **0 failures**.

| Size | Old median | Candidate median | Old p95 | Candidate p95 | Candidate normalized change | 95% bootstrap CI | C/O/T wins |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 KiB | 149.583 ms | 154.184 ms | 222.005 ms | 214.276 ms | -1.189% | [-9.779%, 5.162%] | 14/13/3 |
| 64 KiB | 282.594 ms | 283.504 ms | 437.274 ms | 400.116 ms | 2.835% | [-7.587%, 12.210%] | 13/14/3 |
| 1 MiB | 500.885 ms | 498.590 ms | 731.892 ms | 737.530 ms | -0.833% | [-10.046%, 7.206%] | 17/11/2 |
| 8 MiB | 791.640 ms | 805.937 ms | 1421.704 ms | 1099.337 ms | 0.680% | [-9.903%, 11.735%] | 12/17/1 |

Основной нормализованный результат:

```text
Mean per-size total improvement: 0.373%
Verdict: PRACTICALLY_EQUIVALENT
```

Дополнительные агрегаты, которые не используются как основной verdict из-за смешения размеров:

```text
Old overall median:       458.704 ms
Candidate overall median: 439.882 ms
Candidate difference:     4.103% faster

Old overall p95:          972.125 ms
Candidate overall p95:    921.669 ms
Candidate difference:     5.190% better
```

По total-time pair outcomes:

```text
candidate wins: 56
old wins:       55
ties:           9
```

Баланс `56/55/9` подтверждает отсутствие систематического преимущества одной версии.

### 6.2 Process resource snapshot

| Метрика | Old | Candidate | Оценка |
|---|---:|---:|---|
| CPU delta за прогон | 8.765625 s | 8.625000 s | candidate на 1.604% ниже |
| Private memory delta | 217088 B | 155648 B | candidate ниже на 61440 B |
| Working Set в конце | 5.672 MiB | 5.594 MiB | практически одинаково |
| Handles в конце | 352 | 353 | практически одинаково |

Признаков утечки handles или memory-growth regression нет.

### 6.3 Внешний web benchmark

Дополнительные последовательные прогоны по внешним сайтам дали 0 ошибок:

- candidate-before: 100/100;
- old: 100/100;
- candidate-after: 100/100;
- SmartProxy-equivalent: 100/100.

Результаты внешних сайтов использовались только как smoke/performance context. CDN, TLS, меняющееся содержимое и сетевой drift делали их недостаточно строгими для решения performance gate. Fixed endpoint устранил эту неоднозначность.

## 7. Ограничения

1. Candidate ещё не прошла повторный deterministic UDP-seed → TCP-same-port C1 в полном real-WinDivert runtime.
2. Destination не входит в near-term key; concurrent flows с одним protocol/family/local endpoint и разными destinations могут обновлять одно value. Full 5-tuple требует отдельного pending-relay index и UDP session redesign.
3. MSVC build не проверен в этой среде; validation выполнена MinGW-w64/GCC.
4. Mixed EOL в `ProxyBridge.c` не следует нормализовывать до фиксации финального tested source/DLL relationship.
5. Performance result доказывает отсутствие измеримой обычной regressии, но не является универсальной оценкой всех workloads.

## 8. Итоговый статус

```text
Defect reproduction on old build:       CONFIRMED
Root cause:                              CONFIRMED
Exact-key implementation:                COMPLETE
#206 exact-decision reconciliation:      COMPLETE
Unit/build/export gates:                 PASS
Targeted TCP/UDP probes:                 PASS
Canary smoke:                            PASS
Fixed-endpoint performance:              PRACTICALLY_EQUIVALENT
Memory/handles regression:               NOT DETECTED
Publish findings in issue:               GO
Continue candidate canary:               GO
Claim full real-runtime collision fix:   HOLD pending one candidate C1 rerun
Merge/PR without caveats:                HOLD
```

## 9. Рекомендуемый следующий шаг

Перед PR или окончательной формулировкой “fixed” выполнить один deterministic C1 A/B:

```text
old build: UDP P -> A, then TCP P -> B => collision/timeout expected
candidate:  same exact test             => TCP rule lookup and success expected
```

Повторять широкие performance benchmarks не требуется.
