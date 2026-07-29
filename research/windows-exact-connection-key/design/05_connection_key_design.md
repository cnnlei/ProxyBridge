# Этап 5 — read-only аудит `connection_hash_table` и production-дизайн исправления C1

Дата аудита: 2026-07-24T16:10:01.180+05:00  
Production-база: `D:\Git\ProxyBridge\Windows\src\ProxyBridge.c`  
Ветка: `fix/windows-udp-stale-fdset`  
HEAD: `1f18417c4075167d595a95e4ce9e3999e5dc8d6d`

## Краткий итог

Для ближайшего production-исправления рекомендуется единый relay-correlation key:

`IPPROTO_TCP/IPPROTO_UDP + AF_INET/AF_INET6 + original local source address + source port`

То есть не только `protocol + source_port`, а полный локальный transport endpoint с protocol и address family.

Этот ключ:

- устраняет подтверждённый TCP/UDP C1;
- не позволяет IPv4 и IPv6 перезаписывать или находить друг друга;
- не позволяет двум локальным адресам с одинаковым numeric port находить одну запись;
- доступен на packet path;
- может быть однозначно восстановлен TCP relay из accepted socket;
- может быть восстановлен UDP relay, но для этого текущий `recvfrom()` необходимо заменить на `WSARecvMsg()` с `IP_PKTINFO`/`IPV6_PKTINFO`.

Таблица в ближайшем patch set остаётся не полной flow table, а таблицей корреляции packet path → local relay. Destination хранится как значение записи, но не входит в первичный ключ. Это намеренно сохраняет текущее UDP-поведение. Полная 5-tuple flow table и destination-aware UDP session mapping должны быть отдельной следующей задачей.

Найдено:

- 23 исполняемых вызова helper-функций таблицы;
- ещё 2 текстовых вызова находятся в macro `ACCEPT_AND_DISPATCH`, которое нигде не вызывается;
- 2 дополнительных исполняемых участка обращаются к таблице напрямую: IPv4 UDP reverse scan и финальная очистка при остановке.

Оценка ближайшего patch set: **medium risk**. Причина — изменение центрального packet/relay correlation path сразу для TCP/UDP и IPv4/IPv6, а также необходимость ancillary packet info в UDP relay. Риск ограничен тем, что не меняются профили, правила, proxy protocol, GUI API, `port_decided_bitmap`/`port_direct_bitmap` и stale-`fd_set` исправления.

---

## A. Preflight

| Проверка | Результат |
|---|---|
| Репозиторий существует | `D:\Git\ProxyBridge` — да |
| Branch | `fix/windows-udp-stale-fdset` — совпадает |
| HEAD | `1f18417c4075167d595a95e4ce9e3999e5dc8d6d` — совпадает |
| `git status --short` | пустой |
| `2c28b9e` ancestor HEAD | да |
| `1f18417` ancestor HEAD | да |
| Запущенный ProxyBridge | PID 15424 |
| Executable path | `C:\ProxyBridge-Sendto-Fix-App\ProxyBridge.exe` |
| Process creation time | `2026-07-24 15:42:01` |
| Другой запущенный `ProxyBridge.exe` | не найден |

Preflight был только read-only. Process не останавливался и не перезапускался.

Для runtime-подтверждения прочитаны только разрешённые журналы:

- `C:\ProxyBridge-ConnHash-Diag-App\logs\collision.jsonl`;
- `C:\ProxyBridge-ConnHash-Diag-App\logs\proxybridge-c1.log`;
- `C:\ProxyBridge-ConnHash-Diag-App\logs\endpoint.jsonl`.

Они не изменялись.

---

## B. Полная карта таблицы соединений

### B.1. Структура и устройство

`CONNECTION_INFO` определена в `ProxyBridge.c:81-93`:

- `src_port`;
- IPv4 `src_ip`, `orig_dest_ip`;
- `orig_dest_port`;
- `is_tracked`;
- `last_activity`;
- `proxy_config_id`;
- `is_ipv6`;
- IPv6 `src_ip6[16]`, `orig_dest_ip6[16]`;
- `next`.

Критически важно: source address уже хранится, но почти нигде не участвует в equality. Protocol вообще не хранится.

Таблица:

- `CONNECTION_HASH_SIZE = 4096` (`ProxyBridge.c:32`);
- `connection_hash_table[4096]` (`ProxyBridge.c:162`);
- каждый bucket — односвязный список;
- текущий hash во всех primary lookup-функциях: `src_port % 4096`;
- отдельной hash-функции нет;
- при обычной работе `add_connection*()` поддерживает не более одной записи на один numeric `src_port` во всей таблице, независимо от protocol, family и local address.

Блокировка:

- глобальный `SRWLOCK lock` (`ProxyBridge.c:167`);
- shared lock для lookup и reverse scan;
- exclusive lock для add/update/remove/cleanup/clear;
- тот же `lock` также используется PID cache и списком уже залогированных соединений;
- `g_rules_lock` — отдельный и к connection table не относится.

Время жизни:

- NEW/UPDATE получает `last_activity = GetTickCount64()`;
- `get_connection*()` обновляет `last_activity`;
- `is_connection_tracked()` время не обновляет;
- cleanup worker просыпается раз в 30 секунд (`ProxyBridge.c:5305-5316`);
- connection entry удаляется при возрасте более 120 000 ms (`ProxyBridge.c:4257`);
- TCP FIN/RST вызывает `remove_connection()` в четырёх packet-path местах;
- `ProxyBridge_Stop()` очищает все buckets (`ProxyBridge.c:5596-5606`).

### B.2. Все операции и фактический matching

| Функция | Строки | Matching | Lock | Вывод |
|---|---:|---|---|---|
| `add_connection` | 3998-4039 | UPDATE только по `src_port` | exclusive | может перезаписать UDP/TCP, IPv4/IPv6 или другой local IP |
| `add_connection_v6` | 4041-4082 | UPDATE только по `src_port` | exclusive | та же проблема; UPDATE меняет family записи |
| `get_connection_full_v6` | 4084-4103 | `src_port && is_ipv6` | shared | family проверяет, protocol и source IP — нет |
| `find_v6_udp_sender` | 4106-4128 | IPv6 + original destination address/port, затем newest activity | shared | protocol и proxy config не проверяет |
| `is_connection_tracked` | 4130-4147 | `src_port && is_tracked` | shared | полностью слеп к protocol/family/address/destination |
| `get_connection` | 4149-4173 | только `src_port` | shared | может вернуть даже IPv6 node как IPv4 zeros |
| `get_connection_full` | 4175-4200 | только `src_port` | shared | та же проблема, плюс возвращает config |
| `get_connection_proxy_id` | 4202-4223 | только `src_port` | shared | отдельный второй snapshot |
| `remove_connection` | 4225-4244 | только `src_port` | exclusive | может удалить запись другого protocol/family/address |
| `cleanup_stale_connections` | 4246-4271 | age, обход всех buckets | exclusive с unlock/relock внутри обхода | key не использует; текущий cursor небезопасен при конкурентном remove |

Прямые обращения:

1. `ProxyBridge.c:3461-3490` — IPv4 UDP reverse scan по original destination, newest `last_activity`. Проверяется `!is_ipv6`, но не protocol и не `proxy_config_id`.
2. `ProxyBridge.c:5596-5606` — полная очистка таблицы при остановке.

### B.3. Все исполняемые call sites

Обозначения:

- `да` — значение уже доступно до вызова;
- `out` — появляется только из результата lookup;
- `recoverable` — значение есть в socket/packet metadata, но текущий вызов его не передаёт;
- `нет` — значения нет в текущем месте;
- под source понимается **original local source endpoint**, который должен войти в рекомендуемый key.

| # | Call site | Protocol | Family | Source IP | Source port | Destination IP | Destination port | PID | Proxy config | Цель |
|---:|---|---|---|---|---|---|---|---|---|---|
| 1 | `get_connection_full_v6:532` | UDP | IPv6 | да: packet `DstAddr` | `client_sp` | out | out | нет | out, сейчас dummy | packet-path relay-response lookup |
| 2 | `is_connection_tracked:546` | UDP | IPv6 | да: `SrcAddr` | `sp` | да: `DstAddr` | `dp` | ещё нет | ещё нет | packet-path tracked lookup |
| 3 | `add_connection_v6:628` | UDP | IPv6 | да: `SrcAddr` | `sp` | да: `DstAddr` | `dp` | `pid6u` | `pcid6u` | insert/update |
| 4 | `get_connection_full_v6:708` | TCP | IPv6 | recoverable из packet direction | `client_sp` | да: второй packet address | out | нет | out, dummy | packet-path relay-response lookup |
| 5 | `remove_connection:722` | TCP | IPv6 | recoverable из packet direction | `client_sp` | да | из предыдущего lookup | нет | из предыдущего lookup | remove FIN/RST |
| 6 | `is_connection_tracked:726` | TCP | IPv6 | да: `SrcAddr` | `sp` | да: `DstAddr` | `dp` | ещё нет | ещё нет | packet-path tracked lookup |
| 7 | `remove_connection:728` | TCP | IPv6 | да: `SrcAddr` | `sp` | да: `DstAddr` | `dp` | нет | нет | remove FIN/RST |
| 8 | `add_connection_v6:830` | TCP | IPv6 | да: `SrcAddr` | `sp` | да: `DstAddr` | `dp` | `pid6` | `proxy_config_id6` | insert/update |
| 9 | `get_connection:874` | UDP | IPv4 | да: packet `DstAddr` | `dst_port` | out | out | нет | нет | packet-path relay-response lookup |
| 10 | `is_connection_tracked:899` | UDP | IPv4 | да: `SrcAddr` | UDP `SrcPort` | да: `DstAddr` | UDP `DstPort` | ещё нет | ещё нет | packet-path tracked lookup |
| 11 | `add_connection:1004` | UDP | IPv4 | `src_ip` | `src_port` | `dest_ip` | `dest_port` | `pid` | `proxy_config_id` | insert/update |
| 12 | `get_connection:1106` | TCP | IPv4 | recoverable из packet direction | `dst_port` | да: второй packet address | out | нет | нет | packet-path relay-response lookup |
| 13 | `remove_connection:1123` | TCP | IPv4 | recoverable из packet direction | `dst_port` | да | из предыдущего lookup | нет | нет | remove FIN/RST |
| 14 | `is_connection_tracked:1125` | TCP | IPv4 | да: `SrcAddr` | TCP `SrcPort` | да: `DstAddr` | TCP `DstPort` | ещё нет | ещё нет | packet-path tracked lookup |
| 15 | `remove_connection:1131` | TCP | IPv4 | `src_ip`/packet `SrcAddr` | `src_port` | packet `DstAddr` | packet `DstPort` | нет | нет | remove FIN/RST |
| 16 | `add_connection:1239` | TCP | IPv4 | `src_ip` | `src_port` | `orig_dest_ip` | `orig_dest_port` | `pid` | `proxy_config_id` | insert/update |
| 17 | `get_connection:3350` | UDP | IPv4 | recoverable: peer, только если peer и packet-info destination оба loopback; иначе `IP_PKTINFO` destination | `from_port` | роль `from_addr` зависит от rewrite; stored value приходит out | out | нет | нет | UDP relay request lookup |
| 18 | `get_connection_proxy_id:3352` | UDP | IPv4 | как выше | `from_port` | уже out предыдущего lookup | уже out предыдущего lookup | нет | out | второй UDP relay lookup |
| 19 | `find_v6_udp_sender:3518` | UDP | IPv6 | out | out | да: SOCKS5 UDP response address | да: SOCKS5 UDP response port | нет | да: enclosing `cfg`, сейчас не передаётся | reverse relay lookup |
| 20 | `get_connection_full_v6:3546` | UDP | IPv6 | recoverable: `IPV6_PKTINFO` destination; для `::1 -> ::1` peer совпадает | `from_port` | роль peer зависит от rewrite; stored value приходит out | out | нет | out | UDP relay request lookup |
| 21 | `get_connection_full:3706` | TCP | IPv4 | recoverable из accepted peer + `getsockname()` | `client_addr.sin_port` | recoverable из peer/local pair | нет: original destination port уже заменён relay port | нет | out | TCP relay lookup |
| 22 | `get_connection_full_v6:3733` | TCP | IPv6 | recoverable из accepted peer + `getsockname()` | `client_addr6.sin6_port` | recoverable из peer/local pair | нет | нет | out | TCP relay lookup |
| 23 | `cleanup_stale_connections:5313` | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | cleanup |

Неисполняемые textual call sites:

- `get_connection_full_v6:3683`;
- `get_connection_full:3684`.

Оба находятся внутри `ACCEPT_AND_DISPATCH` (`ProxyBridge.c:3674-3689`). Macro определяется и затем удаляется через `#undef`, но нигде не вызывается. Поэтому они не входят в число 23. Дополнительно в macro читается ещё не инициализированный `cc->is_ipv6`; это статическое наблюдение, а не часть текущего runtime path.

### B.4. Проверка специальных путей

#### Первый TCP SYN

На fresh SYN удаляется только PID cache (`ProxyBridge.c:1077-1083`). После этого код всё равно может пройти через `is_connection_tracked(src_port)` (`1125`). Поэтому stale connection entry с тем же numeric port может перехватить новый SYN раньше rule lookup.

#### `local_proxy_server`

IPv4 listener привязан к `0.0.0.0`, IPv6 listener — к `[::]` с `IPV6_V6ONLY=1` (`3585-3656`). После `accept()` lookup выполняется только по peer numeric port (`3705-3706`, `3732-3733`).

Для non-loopback WinDivert меняет:

`A:P -> B:D` на synthetic inbound `B:P -> A:relay_port`.

Поэтому accepted socket содержит:

- peer = `B:P`;
- local, получаемый через `getsockname()`, = `A:relay_port`.

Original source key восстанавливается как `protocol=TCP, family, A, P`.

Для loopback адреса не меняются; original source находится в peer address. Корректный helper должен получать peer и local address и выбирать:

- оба loopback → peer address;
- иначе → accepted socket local address.

[Microsoft `getsockname`](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-getsockname) подтверждает, что после `accept` локальный адрес connected socket доступен даже при wildcard listener.

#### `connection_handler`

`connection_handler` (`3755-3890`) connection table больше не читает. Он получает уже выбранные destination/config в `CONNECTION_CONFIG`, освобождает структуру и использует snapshot для SOCKS5/HTTP CONNECT. Поэтому ошибочный `get_connection_full*()` непосредственно превращается в ошибочный routing decision.

#### `udp_relay_server`

Есть один IPv4 local relay socket на `0.0.0.0:34011` и один IPv6 socket на `[::]:34011`, причём IPv6 socket явно `V6ONLY` (`3196-3237`). Каждый `PROXY_CONFIG` содержит собственную shared SOCKS5 UDP ASSOCIATE (`udp_tcp_ctrl`, `udp_send_sock`, `udp_relay_addr`, `udp_connected`).

Текущий `recvfrom()` даёт peer address, но не local destination address. После non-loopback rewrite peer — original remote destination, а local destination — original local source address. Поэтому для source-address key одного `recvfrom()` недостаточно.

Нужны:

- `IP_PKTINFO` + `WSARecvMsg` для IPv4;
- `IPV6_PKTINFO` + `WSARecvMsg` для IPv6;
- для IPv4: если peer и ancillary destination оба loopback, original source address берётся из peer; во всех остальных случаях — из ancillary destination;
- для IPv6 ancillary destination достаточен: при единственном no-swap случае `::1 -> ::1` peer и destination совпадают.

[Microsoft `recvfrom`](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-recvfrom) документирует возврат peer/source address. [Microsoft `IN_PKTINFO`](https://learn.microsoft.com/en-us/windows/win32/api/ws2ipdef/ns-ws2ipdef-in_pktinfo) документирует destination IPv4 address в ancillary data `WSARecvMsg`. [Dual-stack guidance](https://learn.microsoft.com/en-us/windows/win32/winsock/dual-stack-sockets) описывает packet-info requirements для IPv6/dual-stack.

---

## C. Точная модель текущей ошибки

### C.1. Почему возникает C1

1. UDP `192.168.0.136:55123 -> 193.124.56.249:41001` создаёт tracked entry с `src_port=55123`.
2. Затем первый TCP SYN `192.168.0.136:55123 -> 193.124.56.249:41002` до rule lookup вызывает `is_connection_tracked(55123)`.
3. Функция видит UDP entry, потому что сравнивает только `src_port` и `is_tracked`.
4. TCP packet получает `actual_path=TRACKED_REDIRECT`; `check_process_rule()` не вызывается, TCP entry не добавляется.
5. Если local TCP accept path получает соединение, `get_connection_full(55123)` по той же причине возвращает destination/config UDP entry, а `connection_handler` использует этот snapshot.

Runtime evidence:

- `collision.jsonl:2-7` подтверждает UDP bind/send/echo на local `192.168.0.136:55123`;
- `collision.jsonl:9-13` подтверждает последующий TCP bind к тому же local endpoint и connect к `:41002`;
- `proxybridge-c1.log:8` — `CONN_ADD ... protocol=UDP ... destination=:41001`;
- `proxybridge-c1.log:9-12` — TCP request matched UDP entry, `protocol_collision=1`, `destination_collision=1`, `actual_path=TRACKED_REDIRECT`, `rule_lookup_called=0`.

Журнал напрямую доказывает ошибочный tracked decision и bypass rules. Следующий wrong-destination relay decision следует из production source: IPv4 `get_connection_full()` также сравнивает только numeric port, а `connection_handler` доверяет его snapshot.

### C.2. Какие функции сравнивают только `src_port`

Строго только `src_port`:

- UPDATE в `add_connection`;
- UPDATE в `add_connection_v6`;
- `is_connection_tracked` (дополнительно проверяется только state flag);
- `get_connection`;
- `get_connection_full`;
- `get_connection_proxy_id`;
- `remove_connection`.

`get_connection_full_v6` сравнивает `src_port + is_ipv6`, но не protocol и не IPv6 source address.

Reverse UDP operations не используют source-port key:

- IPv4 inline scan ищет original destination + IPv4 flag;
- IPv6 `find_v6_udp_sender` ищет original destination + IPv6 flag.

### C.3. Какие wrong-record операции возможны

| Ошибка | Возможна сейчас | Причина |
|---|---|---|
| Вернуть запись другого protocol | да | protocol не хранится |
| Вернуть запись другой family | да для `is_tracked`, IPv4 `get*`, proxy-id и remove | IPv4 path не проверяет `is_ipv6`; tracked/remove полностью family-blind |
| Вернуть запись другого local IP | да | source address хранится, но equality его не использует |
| Удалить не ту запись | да | `remove_connection(src_port)` |
| UPDATE не той записи | да | оба `add_connection*` ищут существующую запись только по port |
| Выбрать UDP response из другого proxy config | да | reverse scan выполняется внутри конкретного `cfg`, но `conn->proxy_config_id` не фильтруется |
| Получить destination и config из разных snapshots | да | IPv4 UDP relay отдельно вызывает `get_connection`, затем `get_connection_proxy_id` |

### C.4. Почему одного `BOOL is_udp` недостаточно

Если корректно протянуть `is_udp` во все add/get/tracked/remove операции, подтверждённый TCP/UDP C1 исчезнет. Но останутся:

- IPv4/IPv6 collision на одинаковом numeric port;
- одинаковый protocol/port на разных local IP;
- TCP/TCP и UDP/UDP reuse одного source endpoint;
- stale mapping при быстром повторном использовании source endpoint;
- UDP one-socket/multi-destination ambiguity;
- UDP response ambiguity для нескольких clients к одному destination;
- cross-config reverse UDP selection;
- split snapshot `get_connection` + `get_connection_proxy_id`.

Если добавить поле только в структуру или изменить только `is_connection_tracked`, исправление будет частичным: add/get/remove продолжат работать по другой identity.

### C.5. Аналогичные конфликты и Windows semantics

| Сценарий | Вывод |
|---|---|
| TCP/UDP, одинаковые local address/port | **Подтверждено runtime.** Protocol является частью Winsock socket address identity; TCP и UDP могут использовать одинаковое число порта. |
| TCP/TCP | Default explicit bind обычно не допускает второй exact local transport address, но outbound port reuse существует, а Windows может разделять соединения по remote tuple. Кроме того, последовательный reuse после закрытия неизбежно возможен. Source-port-only таблица не может безопасно считать такой port вечной identity. |
| UDP/UDP | Один UDP socket нормально отправляет через `sendto()` в разные destinations. Несколько sockets могут делить address/port с reuse options; разные local addresses с одинаковым port являются разными endpoints. |
| IPv4/IPv6 | Возможен. В коде отдельные AF_INET/AF_INET6 sockets, IPv6 явно `V6ONLY`; numeric port не является cross-family identity. |
| Один port на разных local IP | Возможен. Winsock local name включает family, host address и port; port scalability прямо использует разные local address/port pairs. |
| Быстрый reuse после close | Возможен. Entry живёт до 120 s, FIN/RST может быть потерян, а fresh SYN очищает только PID cache. Точный момент TCP reuse ограничивается transport state/TIME_WAIT, но таблица не может полагаться на отсутствие reuse. |

Источники Windows semantics:

- [`bind`](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-bind): local name состоит из family, host address и port; dynamic ranges могут различаться для TCP/UDP и IPv4/IPv6.
- [`SO_REUSEADDR` / `SO_EXCLUSIVEADDRUSE`](https://learn.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse): reuse одного transport address возможен и может быть неоднозначным.
- [`SO_PORT_SCALABILITY`](https://learn.microsoft.com/en-us/windows/win32/winsock/so-port-scalability): Windows различает local address/port pairs.
- [`SOL_SOCKET` options](https://learn.microsoft.com/en-us/windows/win32/winsock/sol-socket-socket-options): `SO_REUSE_UNICASTPORT` допускает ephemeral port reuse; implicit outbound connect использует auto-reuse behavior.
- [`sendto`](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-sendto): один connectionless socket может выбирать destination для каждой datagram.
- [Dual-stack sockets](https://learn.microsoft.com/en-us/windows/win32/winsock/dual-stack-sockets): IPv6 socket по умолчанию V6-only на современных Windows, если явно не включён dual stack.
- [RFC 7605](https://www.rfc-editor.org/info/rfc7605/): port number демультиплексирует transport endpoint association и assignment относится к конкретным transport protocols.

---

## D. Сравнение вариантов ключа

| Вариант | C1 | Cross-family | Different local IP | Relay lookup | Destination нужен для primary lookup | Текущая UDP-модель | Изменение / regression risk | Lookup / память | Lock/cleanup |
|---|---|---|---|---|---|---|---|---|---|
| 1. `source_port` | нет | нет | нет | легко, но неверно | нет | сохраняет текущие ошибки | ничего / высокий текущий риск | O(1) avg; current memory | текущая схема |
| 2. `protocol + source_port` | да | нет | нет | легко: relay знает protocol | нет | сохраняет first-destination behavior | low complexity, medium regression risk из-за миграции всех APIs | O(1); +1 byte/padding | совместим |
| 3. `protocol + family + source_ip + source_port` | да | да | да | да; TCP через accepted addresses, UDP через packet info | нет | сохраняет текущую one-entry-per-local-UDP-endpoint модель | medium complexity/risk | O(1); нормализованная структура не обязана быть больше current | совместим; equality меняется во всех APIs |
| 4. 5-tuple flow table + pending-relay index | да | да | да | только через второй relay-visible index | да для canonical flow, нет для pending index | напрямую не поддерживает текущий UDP redirect: original destination port теряется до relay | high complexity/risk | два O(1) lookup; больше nodes/references | нужны согласованные lock/lifetime двух индексов |
| Separate TCP/UDP tables, port-only | да | нет | нет | да | нет | да | low/medium, но дублирует код и оставляет family/address bugs | O(1); bucket arrays примерно удваиваются | совместим, но появляется drift двух реализаций |

Память:

- current bucket array на x64: `4096 * 8 = 32 KiB`;
- две port-only таблицы требуют около 64 KiB только на bucket arrays;
- нормализованный вариант 3 может заменить параллельные IPv4/IPv6 поля union-ами и не увеличивать размер current `CONNECTION_INFO`;
- вариант 4 требует canonical flow node плюс pending-index node/reference и отдельное lifetime coordination.

Почему вариант 4 нельзя внедрить как «просто добавить destination в hash»:

- TCP accepted socket не знает original destination port: он уже заменён на relay port;
- UDP local relay также не получает original destination port после rewrite;
- для одного UDP source endpoint несколько original destinations невозможно выбрать только по данным текущего `recvfrom`;
- значит, full 5-tuple требует либо metadata transport между packet path и relay, либо per-flow relay endpoints, либо отдельного session/index protocol.

---

## E. Рекомендуемый production-дизайн

### E.1. Выбранный ключ

```text
protocol       UINT8: IPPROTO_TCP или IPPROTO_UDP
family         ADDRESS_FAMILY: AF_INET или AF_INET6
source_port    UINT16, host byte order
source_address 4 raw network-order bytes для IPv4
               16 raw network-order bytes для IPv6
```

PID, destination, proxy config, tracking flag и generation в key не входят.

Обоснование:

- PID не доступен и не стабилен на relay side;
- destination port потерян при redirect и не может быть primary relay key;
- proxy config — значение routing decision, не socket identity;
- `BOOL is_udp` хуже `IPPROTO_*`: допускает неоднозначное расширение и требует инверсной интерпретации;
- `IPPROTO_TCP`/`IPPROTO_UDP` уже являются стандартными wire-protocol identifiers.

### E.2. Представление структур

Рекомендуемые internal types:

```c
typedef union CONNECTION_ADDRESS {
    UINT32 ipv4;       /* raw network-order address */
    UINT8  ipv6[16];   /* raw network-order address */
} CONNECTION_ADDRESS;

typedef struct CONNECTION_KEY {
    UINT8 protocol;              /* IPPROTO_TCP/IPPROTO_UDP */
    ADDRESS_FAMILY family;       /* AF_INET/AF_INET6 */
    UINT16 source_port;          /* host byte order */
    CONNECTION_ADDRESS source_address;
} CONNECTION_KEY;

typedef struct CONNECTION_SNAPSHOT {
    ADDRESS_FAMILY family;
    CONNECTION_ADDRESS destination_address;
    UINT16 destination_port;
    UINT32 proxy_config_id;
} CONNECTION_SNAPSHOT;
```

`CONNECTION_INFO` должен содержать:

- `CONNECTION_KEY key`;
- `CONNECTION_ADDRESS original_destination_address`;
- `UINT16 original_destination_port`;
- `BOOL is_tracked`;
- `ULONGLONG last_activity`;
- `UINT32 proxy_config_id`;
- `next`.

Текущие `src_ip`, `src_ip6`, `src_port`, `is_ipv6` должны быть заменены нормализованным `key`, а `orig_dest_ip`/`orig_dest_ip6` — destination union. Дублировать одни и те же key-поля одновременно в старом и новом представлении не следует: это создаёт риск рассинхронизации.

`diag_is_udp` и `diag_generation` в production не переносятся. Protocol здесь — correctness field, а не telemetry field.

### E.3. Точная hash function

Использовать 32-bit FNV-1a над канонической последовательностью:

1. один byte `protocol`;
2. один family tag: `4` для AF_INET, `6` для AF_INET6;
3. source port как два bytes в network/canonical order: high byte, затем low byte;
4. 4 или 16 raw address bytes.

```c
static UINT32 connection_key_hash(const CONNECTION_KEY *key)
{
    UINT32 h = 2166136261u;
    UINT8 family_tag = key->family == AF_INET ? 4u : 6u;
    UINT8 port_bytes[2] = {
        (UINT8)(key->source_port >> 8),
        (UINT8)(key->source_port & 0xff)
    };

    h = fnv1a32_update(h, &key->protocol, 1);
    h = fnv1a32_update(h, &family_tag, 1);
    h = fnv1a32_update(h, port_bytes, 2);
    h = fnv1a32_update(
        h,
        key->family == AF_INET
            ? (const UINT8 *)&key->source_address.ipv4
            : key->source_address.ipv6,
        key->family == AF_INET ? 4 : 16);

    return h & (CONNECTION_HASH_SIZE - 1);
}
```

`fnv1a32_update` для каждого byte выполняет:

```c
h ^= byte;
h *= 16777619u;
```

Обязательна compile-time проверка, что `CONNECTION_HASH_SIZE` — power of two. FNV не используется как security hash; bucket chaining обрабатывает hash collisions.

Нельзя hash-ить raw bytes всей C-структуры: padding и неинициализированные bytes сделали бы hash ABI-dependent.

### E.4. Точная equality

```text
protocol равен
AND family равна
AND source_port равен
AND:
  AF_INET  -> UINT32 IPv4 равен
  AF_INET6 -> memcmp(source_address.ipv6, ..., 16) == 0
```

Нельзя использовать `memcmp(CONNECTION_KEY)` целиком из-за padding.

### E.5. Единый API таблицы

Рекомендуется убрать расхождение IPv4/IPv6 helper-функций и второй proxy-id lookup. Internal API:

`CONNECTION_TABLE` должен владеть bucket array и отдельным `SRWLOCK`. Существующий глобальный `lock` после миграции продолжит защищать PID cache/logged state, но больше не будет использоваться connection table. Семантика блокировки остаётся прежней — shared для snapshots, exclusive для mutation — при этом direct traversal вне module запрещён и nested connection/PID locks не требуются.

```c
void connection_table_upsert(
    CONNECTION_TABLE *table,
    const CONNECTION_KEY *key,
    const CONNECTION_ADDRESS *destination_address,
    UINT16 destination_port,
    UINT32 proxy_config_id);

BOOL connection_table_is_tracked(
    CONNECTION_TABLE *table,
    const CONNECTION_KEY *key);

BOOL connection_table_get_full(
    CONNECTION_TABLE *table,
    const CONNECTION_KEY *key,
    CONNECTION_SNAPSHOT *snapshot);

BOOL connection_table_remove(
    CONNECTION_TABLE *table,
    const CONNECTION_KEY *key);

void connection_table_cleanup(
    CONNECTION_TABLE *table,
    ULONGLONG now,
    ULONGLONG ttl_ms);

void connection_table_clear(
    CONNECTION_TABLE *table);

BOOL connection_table_find_udp_sender(
    CONNECTION_TABLE *table,
    ADDRESS_FAMILY family,
    UINT32 proxy_config_id,
    const CONNECTION_ADDRESS *remote_address,
    UINT16 remote_port,
    CONNECTION_KEY *client_key);
```

Правила:

- `upsert` делает UPDATE только при полном `connection_key_equal`;
- `is_tracked`, `get_full` и `remove` используют тот же hash и ту же equality;
- `get_full` атомарно копирует destination + port + proxy config под одним shared lock;
- старые `get_connection`, `get_connection_full_v6`, `get_connection_proxy_id` удаляются после миграции call sites;
- reverse UDP helper проверяет `protocol == IPPROTO_UDP`, family, `proxy_config_id`, remote address и remote port;
- cleanup не выполняет key lookup, но безопасно удаляет stale nodes;
- clear является единственным прямым shutdown traversal;
- никакой `CONNECTION_INFO *` не выходит за пределы lock.

### E.6. Аргументы всех групп call sites

#### Packet path — original outbound

- IPv4 UDP: `IPPROTO_UDP, AF_INET, ip_header->SrcAddr, udp SrcPort`.
- IPv6 UDP: `IPPROTO_UDP, AF_INET6, ipv6_header->SrcAddr, udp SrcPort`.
- IPv4 TCP: `IPPROTO_TCP, AF_INET, ip_header->SrcAddr, tcp SrcPort`.
- IPv6 TCP: `IPPROTO_TCP, AF_INET6, ipv6_header->SrcAddr, tcp SrcPort`.

Один и тот же key передаётся в tracked lookup, add/update и outbound FIN/RST remove.

Fresh TCP `SYN && !ACK` не должен принимать stale tracked shortcut: внутри connection-table path он обязан пройти rule lookup и exact-key upsert. Это не требует изменений `port_decided_bitmap`/`port_direct_bitmap`; bitmap-related behavior остаётся отдельной границей задачи.

#### Packet path — relay response

- UDP IPv4/IPv6: original local source address находится в packet destination address, client source port — packet destination port.
- TCP non-loopback: original local source address находится в текущем packet source address, client source port — packet destination port.
- TCP loopback: original local source address находится в packet destination address, потому что loopback path не меняет IP addresses.

Эту orientation-логику следует централизовать в key-builder helpers, а не повторять в четырёх местах.

#### TCP local relay

После `accept()`:

1. получить peer address/port из `accept`;
2. получить local address accepted socket через `getsockname`;
3. если peer и local loopback — source address = peer address;
4. иначе source address = local address;
5. source port = peer port;
6. protocol = TCP, family = listener family;
7. один `connection_table_get_full()` возвращает destination/config snapshot.

Это однозначно определяет запись в рамках рекомендуемого relay-visible key.

#### UDP local relay

При инициализации local relay sockets:

- включить `IP_PKTINFO` на IPv4 socket;
- включить `IPV6_PKTINFO` на IPv6 socket;
- получить `LPFN_WSARECVMSG` через `WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, WSAID_WSARECVMSG, ...)`.

При приёме datagram:

- source port = peer port;
- IPv4: если peer address и ancillary destination address оба loopback → source address = peer address; иначе source address = ancillary destination address;
- IPv6: source address = ancillary destination address; при `::1 -> ::1` peer и destination совпадают;
- protocol = UDP, family = socket family;
- один `connection_table_get_full()` возвращает destination и config.

Если ancillary destination address отсутствует там, где он обязателен, packet нельзя безопасно сопоставлять по одному port; fallback к port-only запрещён. Datagram следует отбросить с rate-limited diagnostic message.

#### SOCKS5 UDP response

SOCKS5 UDP header возвращает remote endpoint, но не client endpoint. Enclosing loop уже знает `cfg->config_id`. Reverse helper должен получать:

`family + IPPROTO_UDP + cfg id + remote address + remote port`

и возвращать client source key. Это не устраняет неоднозначность нескольких clients к одному remote endpoint, но исключает выбор TCP node, другой family и другого proxy config.

### E.7. Как исключается wrong remove/update

- bucket выбирается hash полного key;
- traversal сравнивает полный key;
- TCP remove никогда не совпадает с UDP entry;
- IPv4 remove никогда не совпадает с IPv6 entry;
- address `A` никогда не совпадает с address `B`;
- UPDATE изменяет payload только exact-key node;
- reverse lookup не используется для remove;
- shutdown/cleanup удаляют конкретный уже отвязанный node, а не запись по numeric port.

### E.8. Canonical flow table и pending relay index

Для ближайшего patch set отдельные структуры **не нужны**. Рекомендуемая таблица сама является pending relay/correlation table и намеренно имеет relay-visible key.

Полная canonical 5-tuple flow table должна быть отдельным последующим redesign. Тогда отдельный pending-relay index станет обязательным, потому что relay не видит original destination port. Нельзя частично заменить primary key на 5-tuple и продолжить relay lookup по source port.

### E.9. Намеренно вне scope

- issue #206;
- `port_decided_bitmap` и `port_direct_bitmap`;
- #207/#208;
- изменение rule evaluation;
- profile/settings/scheduler;
- diagnostic `diag_is_udp`/`diag_generation`;
- полная destination-aware UDP session model;
- новый on-wire protocol между packet path и relay;
- per-flow relay ports/sockets;
- GUI/API changes;
- stale-`fd_set` production fixes, кроме обязательной регрессии.

---

## F. UDP-ограничения

### F.1. Один local UDP socket → несколько destinations

Это нормальная Winsock-модель: destination задаётся каждым `sendto()`.

Текущий ProxyBridge не поддерживает её корректно. После первой записи следующий packet с тем же numeric source port попадает в `is_connection_tracked()` до rule lookup/add. Поэтому existing destination не обновляется: фактически **first tracked destination sticks**, пока запись не удалена/не протухла. Datagram, предназначенная второму destination, relay отправляет первому.

Рекомендуемый source-endpoint key сохраняет это текущее поведение, но не исправляет его. Это не блокирует C1 fix и должно быть отдельной destination-aware UDP session задачей.

### F.2. Несколько local UDP sockets → один destination

При разных source endpoints рекомендуемый key хранит разные nodes. Но SOCKS5 response содержит remote endpoint, а reverse lookup выбирает одну client entry по newest `last_activity`.

Значит, response routing остаётся неоднозначным, особенно при shared SOCKS5 UDP ASSOCIATE. Это не C1, но это отдельный correctness defect UDP session mapping.

### F.3. Shared SOCKS5 UDP ASSOCIATE

У каждого proxy config один `udp_send_sock`/association, используемый всеми его UDP flows. Enclosing receive loop знает конкретный config. Поэтому reverse lookup обязан как минимум фильтровать `proxy_config_id`; иначе response конкретной association может выбрать node другого config.

Фильтрация protocol/family/config должна войти в атомарную миграцию table API. Полный redesign association/session mapping может остаться отдельным.

### F.4. Классификация

| Наблюдение | Классификация |
|---|---|
| UDP relay не имеет original local source IP при обычном `recvfrom` | **Должно быть исправлено одновременно** через packet info; иначе рекомендуемый key невозможно использовать во всех call sites |
| Reverse scan не фильтрует UDP protocol/family/config полностью | **Должно быть исправлено одновременно** с единым table API |
| One socket → multiple destinations: first destination sticks | **Отдельная будущая задача** |
| Several clients → same destination: newest-activity response heuristic | **Отдельная будущая задача** |
| Shared association per proxy config | Не блокирует C1; session redesign — отдельная задача |
| Full 5-tuple UDP table без metadata/index | Не является рабочим C1 patch: relay не сможет выбрать flow |

---

## G. Concurrency и lifetime

### G.1. Что защищает SRWLOCK

- add/update/remove — exclusive;
- lookup/reverse scan — shared;
- scalar/address snapshot копируется до release;
- caller не получает pointer на node;
- `last_activity` обновляется через `InterlockedExchange64`, хотя lookup уже держит shared lock.

Memory safety обычного snapshot lookup корректна: node не может быть освобождён exclusive writer-ом, пока shared lock удерживается.

### G.2. NEW против UPDATE

Сейчас UPDATE определяется только numeric port. После исправления — только exact key.

Из-за раннего `is_connection_tracked`, normal subsequent packets обычно вообще не доходят до UPDATE. UPDATE наиболее реален при гонке двух первых packets или при fresh TCP SYN, который рекомендуется принудительно отправлять через rule/upsert path.

### G.3. Cleanup race

Текущий cleanup:

1. держит exclusive lock;
2. отвязывает stale node;
3. отпускает lock;
4. вызывает `free`;
5. снова берёт lock;
6. продолжает через сохранённый `CONNECTION_INFO **conn_ptr`.

Если `conn_ptr` указывает на `previous->next`, другой writer между пунктами 3 и 5 может удалить/free `previous`. Тогда cursor становится dangling и следующий `*conn_ptr` — use-after-free.

Безопасный вариант:

- под exclusive lock отвязать все stale nodes bucket-а в локальный garbage list;
- не сохранять interior table pointer через unlock;
- отпустить lock;
- освободить только garbage list;
- перейти к следующему bucket.

Либо держать lock во время `free`, но detach-then-free уменьшает время lock hold.

Эта коррекция должна войти в реализацию connection-table module. Аналогичные структуры, использующие тот же unlock/relock pattern вне connection table, не следует молча менять в C1 patch без отдельного scope.

### G.4. Remove race и ABA

Полный recommended key исключает удаление другого protocol/family/address. Но exact same key может быть повторно использован:

- старый flow закрывается;
- новый flow получает тот же protocol/family/local address/port;
- delayed FIN/RST или relay action старого flow удаляет уже новую node.

Fresh TCP SYN forced-upsert уменьшает stale routing, но не создаёт идентификатор поколения, передаваемый relay.

### G.5. Нужен ли generation/token

Один stored `generation` не даёт correctness:

- packet path может увеличить его;
- relay lookup всё равно знает только relay-visible endpoint;
- после overwrite relay прочитает новую generation, но не знает expected old generation;
- token не переносится через текущий redirected TCP/UDP packet.

Поэтому production generation сейчас не рекомендуется. Он может быть диагностикой, но не защитой. Реальная защита exact-key ABA требует transportable token или full flow + pending index, который получает уникальный relay-visible discriminator.

### G.6. Активная запись и timeout

`is_connection_tracked()` не touch-ит activity. UDP relay lookup обычно touch-ит запись на datagram. TCP relay lookup touch-ит её при accept, а response packet lookups touch-ят снова. Длительное одностороннее/тихое TCP соединение всё равно может потерять entry после 120 s. Это existing lifetime behavior, не C1; менять TTL semantics в ближайшем patch не следует без отдельного теста.

---

## H. План тестов

Все перечисленные тесты — проект будущей реализации. На этом этапе они не запускались.

| # | Слой | Вход | Ожидаемый результат | Предотвращает |
|---:|---|---|---|---|
| 1 | Unit, table API | UDP и TCP keys: один family/address/port, разные protocol | две nodes; оба get возвращают свой destination/config | C1 TCP/UDP overwrite/match |
| 2 | Unit, table API | сначала TCP, затем UDP на том же numeric port | обе записи существуют; order не влияет | reverse-order C1 |
| 3 | Unit/control | TCP и UDP на разных source ports | оба обычных lookup проходят | регрессия normal behavior |
| 4 | Unit | IPv4 и IPv6, одинаковые protocol/port | family-specific get; cross-family miss | IPv4/IPv6 collision |
| 5 | Unit | один protocol/port, два local IP | две nodes и отдельные snapshots | local-address collision |
| 6 | Unit | TCP и UDP одного address/port; remove TCP | UDP остаётся | wrong-protocol remove |
| 7 | Unit | две nodes в одном bucket, одна stale | cleanup удаляет только stale; cursor остаётся valid | wrong cleanup и cursor UAF |
| 8 | Unit | upsert с exact key и с key, отличающимся одним полем | exact key обновлён; второй key создаёт отдельную node | partial equality |
| 9 | Runtime C1 harness | существующие CONTROL и COLLISION scenarios | CONTROL проходит; COLLISION соединяется TCP с `:41002`; нет protocol collision; relay snapshot TCP | подтверждённая runtime regression |
| 10 | Integration regression | обе stale-`fd_set` ветки: reconnect/replaced UDP association sockets | stale descriptor не читается; обе production fixes остаются | regressions commits `2c28b9e`, `1f18417` |
| 11 | Unit key-builder | TCP IPv4/IPv6 non-loopback accepted peer/local pairs и loopback pairs | reconstructed source address совпадает с packet-path key | неверная relay address orientation |
| 12 | Integration UDP relay | non-loopback packet info и loopback datagram | WSARecvMsg key совпадает с inserted key; нет port-only fallback | UDP relay lookup miss/wrong local IP |
| 13 | Unit snapshot | destination/config меняются конкурентным upsert между попытками чтения | один `get_full` возвращает internally consistent snapshot | прежний split `get` + `get_proxy_id` |
| 14 | Concurrency stress | barrier-controlled cleanup, remove и upsert в одном bucket | нет dangling cursor/crash; table invariants сохранены | cleanup/remove race |
| 15 | Unit reverse UDP | одинаковый remote endpoint в двух proxy configs и TCP noise node | выбирается только UDP entry нужного family/config | cross-config/protocol reverse match |
| 16 | Packet-path static/integration | stale exact-key TCP entry, затем fresh SYN к новому destination | SYN проходит rule lookup/upsert, relay получает новый destination | fast source-endpoint reuse |

Runtime acceptance details:

- CONTROL: separate ports остаются зелёными;
- COLLISION: UDP `:41001` сначала успешно seed-ится, TCP с тем же local port идёт к `:41002`;
- telemetry/harness не должна обнаруживать `request_protocol=TCP, matched_protocol=UDP`;
- TCP relay snapshot обязан содержать TCP destination/config;
- negative check: no credentials in logs;
- после runtime все temporary profile/process changes проверяются отдельно по procedure будущего этапа.

---

## I. План изменений по файлам

### I.1. Рекомендуемая структура patch set

1. `Windows/src/connection_table.h` — новый internal-only API:
   - `CONNECTION_ADDRESS`;
   - `CONNECTION_KEY`;
   - `CONNECTION_SNAPSHOT`;
   - opaque/internal `CONNECTION_TABLE`;
   - hash/equality/table API declarations.
2. `Windows/src/connection_table.c` — actual production implementation:
   - bucket table;
   - dedicated encapsulated SRW lock;
   - FNV-1a hash;
   - exact equality;
   - upsert/get/tracked/remove;
   - UDP reverse lookup;
   - detach-then-free cleanup;
   - clear.
3. `Windows/src/ProxyBridge.c`:
   - удалить old `CONNECTION_INFO`/table globals после миграции;
   - заменить 23 executable calls;
   - убрать inline IPv4 reverse scan;
   - убрать split proxy-id lookup;
   - добавить key builders для packet orientation;
   - TCP accept: `getsockname` + peer/local orientation;
   - UDP relay: `WSARecvMsg` + packet info;
   - fresh TCP SYN table-path behavior;
   - cleanup worker и Stop используют module API;
   - stale-`fd_set` blocks не менять.
4. `Windows/compile.ps1`:
   - source list вместо единственного `$SourceFile`;
   - добавить `src\connection_table.c` в MSVC и GCC commands;
   - не менять packaging/signing behavior.
5. `Windows/tests/connection_table_tests.c` — tests 1-8, 11, 13-15.
6. `Windows/tests/run_connection_table_tests.ps1` — отдельный deterministic test build, не запускающий ProxyBridge/WinDivert.
7. Существующий C1 harness/endpoint — использовать только на отдельном разрешённом runtime-этапе для test 9; не копировать diagnostic fields в production.

Public `Windows/src/ProxyBridge.h`, GUI/profile и CLI менять не требуется.

### I.2. Приблизительные production-участки

- структура/global table: `ProxyBridge.c:81-93`, `162`, `167-172`;
- IPv6 packet paths: `519-846`;
- IPv4 UDP: `864-1023`;
- IPv4 TCP/SYN: `1066-1267`;
- UDP socket init/loop: `3196-3565`;
- TCP local relay: `3585-3744`;
- old helper implementations: `3998-4271`;
- cleanup worker: `5305-5316`;
- stop clear: `5596-5606`;
- build source lists: `compile.ps1:11-13`, `62-71`, `96-101`.

### I.3. Порядок реализации

1. Зафиксировать clean base/ancestor checks.
2. Добавить production table module и unit tests для key/hash/equality/upsert/get/remove/cleanup.
3. Мигрировать packet-path add/tracked/remove для IPv4/IPv6, TCP/UDP.
4. Мигрировать relay-response packet lookups.
5. Мигрировать TCP accept lookups с peer/local address reconstruction.
6. Мигрировать UDP local receive на packet info и единый snapshot.
7. Перенести оба reverse UDP paths в protocol/family/config-aware helper.
8. Перевести cleanup/clear; удалить old helpers/direct table access.
9. Проверить, что в production source нет `diag_is_udp`/`diag_generation`.
10. Только после code review — build/tests/runtime в отдельно разрешённом этапе.

### I.4. Порядок проверки

1. `git diff --check`.
2. Static search:
   - нет port-only connection-table API;
   - нет прямых table traversals вне module;
   - все 23 call sites мигрированы;
   - dead macro либо удалено, либо не содержит old calls;
   - no changes в bitmap logic и stale-`fd_set` blocks.
3. Unit tests MSVC/GCC.
4. Production compile MSVC/GCC.
5. Static/import checks артефактов.
6. Runtime CONTROL.
7. Runtime COLLISION.
8. IPv4/IPv6/different-local-IP/removal scenarios.
9. Stale-`fd_set` regressions.
10. Final clean source diff review и process/profile integrity checks.

### I.5. «Минимальный diff, который выглядит рабочим, но является неполным»

Опасные упрощения:

- добавить protocol только в `is_connection_tracked`;
- изменить add/tracked, но оставить port-only get/remove;
- добавить `BOOL is_udp`, но не family/source address;
- создать две port-only TCP/UDP таблицы и считать cross-family/address решёнными;
- использовать source-address key на packet path, но fallback к source port в relay;
- передать в UDP key `recvfrom.from_addr` без учёта IP swap и loopback;
- использовать `getsockname` TCP без loopback orientation;
- оставить IPv4 `get_connection` + `get_connection_proxy_id` двумя lock snapshots;
- добавить destination в primary key без pending relay design;
- хранить generation, который relay не может сопоставить с expected token;
- hash/equality через raw `memcmp` padded struct;
- оставить inline IPv4 reverse scan без protocol/config filter;
- изменить cleanup key, но оставить unlock/relock с interior cursor;
- мигрировать только IPv4 или только TCP;
- использовать diagnostic `diag_is_udp` как production key без полной API migration;
- менять `port_decided_bitmap` для маскировки table collision.

---

## J. Решение

### 1. Рекомендуемый ключ

**`IPPROTO_TCP/IPPROTO_UDP + AF_INET/AF_INET6 + original local source address + source port`.**

Destination хранится в snapshot, но не входит в ближайший primary key.

### 2. Нужна ли отдельная TCP pending-relay index

**Нет для ближайшего patch set.** Рекомендуемая таблица сама является pending relay table, а TCP relay восстанавливает key через peer address/port и local address accepted socket.

**Да только для будущей полной 5-tuple architecture**, где canonical flow identity шире relay-visible identity.

### 3. Нужна ли отдельная UDP pending/session index

**Нет для закрытия C1 и сохранения текущей one-entry-per-source-endpoint модели.**

**Да для будущей корректной поддержки one-socket/multi-destination и several-clients/same-destination.** Альтернативой может быть transport metadata или per-flow relay endpoint, но это отдельный redesign.

### 4. Можно ли исправить C1 одним атомарным patch set

**Да**, если атомарно мигрировать:

- key representation;
- hash/equality;
- add/update;
- tracked lookup;
- all get/full operations;
- remove;
- both families and protocols;
- TCP accept key reconstruction;
- UDP packet-info lookup;
- reverse UDP filtering;
- cleanup/clear;
- все 23 executable call sites.

Частичная миграция недопустима.

### 5. Что оставить будущей задачей

- full 5-tuple canonical flow table;
- TCP pending index с уникальным relay discriminator;
- destination-aware UDP session mapping;
- response demultiplexing нескольких UDP clients к одному remote endpoint;
- exact-key ABA/transportable token;
- long-lived idle/unidirectional TCP lifetime policy;
- bitmap issues и #206/#207/#208.

### 6. Риск

**Medium.**

Не low:

- центральный routing path;
- 23 call sites;
- IPv4/IPv6 и TCP/UDP;
- Windows-specific ancillary data;
- concurrent table lifecycle.

Не high:

- ключ доступен без изменения внешнего API/profile/on-wire proxy protocol;
- destination не требуется для primary relay lookup;
- existing chained hash + SRWLOCK model сохраняется;
- полная UDP session architecture не включается;
- есть конкретные unit/runtime regressions.

### 7. Критерии готовности к реализации

- согласован recommended key и scope будущего UDP redesign;
- подтверждена TCP peer/local orientation для loopback/non-loopback;
- принят обязательный `WSARecvMsg`/packet-info путь без port-only fallback;
- утверждён единый snapshot API вместо IPv4 double lookup;
- все 23 executable calls и 2 direct consumers имеют migration mapping;
- cleanup cursor исправляется detach-then-free;
- generation не выдаётся за correctness без transportable token;
- unit tests покрывают key, update, remove, cleanup и relay builders;
- C1 harness имеет CONTROL/COLLISION acceptance criteria;
- stale-`fd_set` fixes остаются нетронутыми и покрываются regressions;
- implementation выполняется одним reviewable atomic patch set на production base `1f18417`.

---

## Финальное подтверждение границ этапа

- Исходные файлы не изменялись.
- Diagnostic source не использовался как production base.
- Ничего не собиралось.
- ProxyBridge/harness/endpoint не запускались.
- ProxyBridge не останавливался и не перезапускался.
- Branch/commit/stash/worktree/PR/issue не создавались.
- `port_decided_bitmap`/`port_direct_bitmap` не изменялись.
- Отчёт является только read-only архитектурным проектом.
