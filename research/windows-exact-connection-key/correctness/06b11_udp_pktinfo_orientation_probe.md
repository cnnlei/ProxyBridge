# 6B.11 — UDP WSARecvMsg/pktinfo orientation probe

## Итог

PASS.

Production UDP pktinfo reception, ancillary parsing and exact-key
orientation подтверждены для IPv4 и IPv6.

## Зафиксированные файлы

ProxyBridge.c SHA-256:

4C5EF72F33C9144EB1FE7033D299DEC900EB32FFD75DCA37186A7DC0ABA29825

Probe source SHA-256:

88B40DFBC1D81DC7BEECEA65A3EC12CF3419968A71BC290F518336199DD1EBFB

Probe EXE SHA-256:

E1E10652E9C8D4BC0BBD99F04B44B1B68E53B83F4F5A8FF670DAA093775FEBDA

Probe run report SHA-256:

917D2FA2227432EC93B95A16E82D5ACF9F338377D6D296AA9668E212FC7822A5

## Build

- GCC build exit code: 0
- Probe EXE size: 178335 bytes
- GNU11 / MinGW-w64
- Production ProxyBridge.c включён непосредственно в probe translation unit
- connection_table.c компилировался отдельно

Warnings относились к существующему production source и не блокировали probe.

## Результаты

- PASS ipv4_loopback
- PASS ipv4_normal
- PASS ipv6_loopback
- PASS ipv6_normal
- PASS synthetic_orientation
- PASS parser_validation
- SUMMARY: 6 passed, 0 failed
- RUN_EXIT_CODE: 0

## Доказанный live-контракт

- IPv4 receiver получает concrete IP_PKTINFO destination.
- IPv6 receiver получает concrete IPV6_PKTINFO destination.
- WSARecvMsg extension pointer получается на реальном socket.
- IPv4 и IPv6 loopback key используют peer address.
- IPv4 и IPv6 normal key используют pktinfo destination.
- Source port берётся из UDP peer endpoint.
- Port-only fallback отсутствует.
- Exact-table marker round-trip проходит для всех четырёх live cases.

## Synthetic orientation

- IPv4 normal выбирает destination marker, а не peer trap.
- IPv4 distinct loopback выбирает peer marker, а не destination trap.
- IPv6 normal выбирает destination marker, а не peer trap.
- IPv6 loopback сохраняет loopback source address и peer source port.

## Builder validation

Подтверждено отклонение:

- source port 0;
- unspecified peer;
- unspecified pktinfo destination;
- mixed loopback/non-loopback в обеих ориентациях;
- IPv4-mapped IPv6 peer;
- IPv4-mapped IPv6 pktinfo destination;
- wrong sockaddr family;
- NULL arguments.

## Ancillary parser validation

Корректные synthetic IPv4 и IPv6 WSAMSG принимаются.

Подтверждено отклонение:

- callback SOCKET_ERROR;
- MSG_TRUNC;
- MSG_CTRUNC;
- missing pktinfo;
- wrong peer family;
- wrong ancillary level;
- wrong ancillary type;
- слишком маленький cmsg_len;
- неверный pktinfo cmsg_len;
- oversized Control.len;
- received_bytes больше payload capacity.

## Ограничения запуска

- Production globals не присваивались.
- ProxyBridge_Start не вызывался.
- udp_relay_server не запускался.
- WinDivert не открывался.
- SOCKS5 UDP ASSOCIATE не создавался.
- Candidate DLL не запускалась.
- Candidate DLL не развёртывалась.

## Решение

UDP WSARecvMsg/pktinfo targeted gate закрыт.

TCP endpoint-orientation gate также закрыт.

До полноценного runtime остаётся обязательная сверка границы
с исправлением #206 и bitmap semantics.

Это не является разрешением на deployment production candidate.
