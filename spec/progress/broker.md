# Lane progress: broker

Rows follow 06-agent-loop.md §13.

| chunk | status | attempts | last evidence folder | note |
|---|---|---|---|---|
| M2.1 | DONE | 1 | evidence/M2.1/20261116T233700Z | local explicit proxy: session table (token+client-IP), 407/403 denials with effect.denied/effect.http records, hop-by-hop stripping, CONNECT host/port policy. 2/2 sabotages caught |
| M2.2 | DONE | 1 | evidence/M2.2/20261116T233703Z | TLS interception: per-session P-256 CA, per-host leaf LRU (4096), ALPN h2+h1 client-side, upstream verify vs system+fixture roots (TLS>=1.2), SNI/Host/authority cross-checks, key confined to keystore. 3/3 sabotages caught |
| M2.3 | DONE | 1 | evidence/M2.3/20261116T233711Z | streaming both directions <= bufferLimit on the fly SHA-256, flush per write (1000 SSE events distinct reads, p99 added delay <2ms), trailers preserved, client-abort cancels upstream within 1s, 1GiB upload/download byte-equal at bounded RSS. 3/3 sabotages caught |
