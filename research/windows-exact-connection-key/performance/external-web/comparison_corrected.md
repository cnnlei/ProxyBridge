# Corrected proxy path benchmark comparison

Positive improvement means ProxyBridge is better.

| Route | Target | Metric | SmartProxy median | ProxyBridge median | SmartProxy p95 | ProxyBridge p95 | Improvement | Verdict |
|---|---|---:|---:|---:|---:|---:|---:|---|
| DIRECT | Example | TotalMs | 199.245 | 204.553 | 455.254 | 227.049 | -2.664% | EQUIVALENT |
| DIRECT | Example | TtfbMs | 199.157 | 204.49 | 455.199 | 226.974 | -2.678% | EQUIVALENT |
| DIRECT | Example | ConnectMs | 49.918 | 53.266 | 61.512 | 71.684 | -6.707% | PROXYBRIDGE_WORSE |
| DIRECT | Example | TlsReadyMs | 146.767 | 152.417 | 404.166 | 174.043 | -3.849% | PROXYBRIDGE_SLIGHTLY_WORSE |
| DIRECT | Example | SpeedBytesPerSecond | 1947.0 | 1896.5 | 2041.65 | 1982.15 | -2.594% | EQUIVALENT |
| DIRECT | Wikipedia | TotalMs | 511.78 | 368.731 | 1826.537 | 676.395 | 27.951% | PROXYBRIDGE_MUCH_BETTER |
| DIRECT | Wikipedia | TtfbMs | 411.798 | 294.816 | 1722.003 | 609.709 | 28.408% | PROXYBRIDGE_MUCH_BETTER |
| DIRECT | Wikipedia | ConnectMs | 71.718 | 73.041 | 1074.721 | 88.346 | -1.845% | EQUIVALENT |
| DIRECT | Wikipedia | TlsReadyMs | 255.222 | 210.846 | 1440.067 | 519.66 | 17.387% | PROXYBRIDGE_MUCH_BETTER |
| DIRECT | Wikipedia | SpeedBytesPerSecond | 59899.0 | 83081.5 | 88554.35 | 88471.65 | 38.703% | PROXYBRIDGE_MUCH_BETTER |
| PROXY | ChatGPT | TotalMs | 185.356 | 195.327 | 254.064 | 230.956 | -5.38% | PROXYBRIDGE_WORSE |
| PROXY | ChatGPT | TtfbMs | 183.501 | 195.213 | 253.952 | 230.643 | -6.382% | PROXYBRIDGE_WORSE |
| PROXY | ChatGPT | ConnectMs | 0.413 | 50.398 | 1.184 | 52.655 |  | NOT_COMPARABLE |
| PROXY | ChatGPT | TlsReadyMs | 125.53 | 146.214 | 151.256 | 176.588 | -16.477% | PROXYBRIDGE_MUCH_WORSE |
| PROXY | ChatGPT | SpeedBytesPerSecond | 26106.5 | 16785.5 | 27824.6 | 23864.75 | -35.704% | PROXYBRIDGE_MUCH_WORSE |
| PROXY | GitHub | TotalMs | 372.883 | 369.208 | 396.323 | 408.513 | 0.986% | EQUIVALENT |
| PROXY | GitHub | TtfbMs | 274.74 | 260.419 | 291.203 | 305.013 | 5.213% | PROXYBRIDGE_BETTER |
| PROXY | GitHub | ConnectMs | 0.407 | 5.472 | 10.672 | 25.173 |  | NOT_COMPARABLE |
| PROXY | GitHub | TlsReadyMs | 197.972 | 188.428 | 209.865 | 225.979 | 4.821% | PROXYBRIDGE_SLIGHTLY_BETTER |
| PROXY | GitHub | SpeedBytesPerSecond | 341273.5 | 344614.5 | 567790.35 | 557262.6 | 0.979% | EQUIVALENT |
| PROXY | YouTube | TotalMs | 426.393 | 433.845 | 517.538 | 506.15 | -1.748% | EQUIVALENT |
| PROXY | YouTube | TtfbMs | 242.319 | 250.925 | 292.517 | 278.514 | -3.551% | PROXYBRIDGE_SLIGHTLY_WORSE |
| PROXY | YouTube | ConnectMs | 0.408 | 5.768 | 24.791 | 25.083 |  | NOT_COMPARABLE |
| PROXY | YouTube | TlsReadyMs | 132.379 | 138.625 | 164.61 | 158.154 | -4.719% | PROXYBRIDGE_SLIGHTLY_WORSE |
| PROXY | YouTube | SpeedBytesPerSecond | 572672.0 | 559916.5 | 708083.7 | 686782.15 | -2.227% | EQUIVALENT |

## Overall

- SmartProxy-equivalent median total: 361.519 ms
- ProxyBridge median total: 346.981 ms
- ProxyBridge median improvement: 4.021%
- SmartProxy-equivalent p95 total: 842.272 ms
- ProxyBridge p95 total: 480.733 ms
- ProxyBridge p95 improvement: 42.924%

## Important caveats

- PROXY ConnectMs is not comparable: explicit SOCKS curl measures the local SOCKS connection, while transparent ProxyBridge measures the application's original connection path.
- ChatGPT returned HTTP 403 in both modes and response sizes differed, so its download-speed result is not a valid throughput comparison.
- The two modes were measured sequentially, so one reverse-order confirmation run is needed before claiming a causal performance advantage.
