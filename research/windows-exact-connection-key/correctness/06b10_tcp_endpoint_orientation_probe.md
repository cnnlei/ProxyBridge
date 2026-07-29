# 6B.10 — TCP endpoint-orientation probe

## Итог

PASS.

Production accepted-socket reconstruction подтверждена для IPv4 и IPv6.

## Зафиксированные файлы

ProxyBridge.c SHA-256:

4C5EF72F33C9144EB1FE7033D299DEC900EB32FFD75DCA37186A7DC0ABA29825

Probe source SHA-256:

F2ED52FDE17026F0723734FBA2173090E2ED4245DB0C034968DEA1EE22EE8112

Probe source delta SHA-256:

050CFD952F234E6E4AEE6992215E07570B159817B5AC3B877ACFF3BDC7BB541C

Probe EXE SHA-256:

D96F056A15B7F162FB3E4E20657A6471088E699F2D1F688E75F10377C6F11444

Probe run report SHA-256:

A4B083F07F313EECC4CE2DE1F4CB3B25804C76A8B5A0367C8A84D137C52F2057

## Build

- GCC build exit code: 0
- Probe EXE size: 180397 bytes
- GNU11/MinGW-w64
- Production ProxyBridge.c был включён непосредственно в probe translation unit
- connection_table.c компилировался отдельно

Warnings относились к существующему production source и не блокировали probe.

## Результаты

- PASS ipv4_loopback
- PASS ipv4_normal
- PASS ipv6_loopback
- PASS ipv6_normal
- PASS negative_validation
- SUMMARY: 5 passed, 0 failed
- RUN_EXIT_CODE: 0

## Доказанный контракт

- Loopback TCP key использует peer address.
- Normal TCP key использует accepted local address.
- Source port берётся из accepted peer endpoint.
- Accepted local port обязан совпадать с g_local_relay_port.
- Mixed loopback/non-loopback tuples отклоняются.
- Port zero отклоняется.
- Unspecified addresses отклоняются.
- IPv4-mapped IPv6 отклоняется.
- Expected marker выбирается при одновременно существующем trap marker.
- Accepted socket остаётся валидным после production lookup.

## Ограничения запуска

- ProxyBridge_Start не вызывался.
- Service workers не запускались.
- WinDivert не открывался.
- Candidate DLL не запускалась.
- Candidate DLL не развёртывалась.

## Решение

TCP endpoint-orientation gate закрыт.

GO для UDP WSARecvMsg/pktinfo targeted probe.

Это не является разрешением на запуск или deployment полной candidate DLL.
