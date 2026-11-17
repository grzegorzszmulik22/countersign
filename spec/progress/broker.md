# Lane progress: broker

Rows follow 06-agent-loop.md §13.

| chunk | status | attempts | last evidence folder | note |
|---|---|---|---|---|
| M2.1 | DONE | 1 | evidence/M2.1/20261117T003115Z | local explicit proxy: session table (token+client-IP), 407/403 denials with effect.denied/effect.http records, hop-by-hop stripping, CONNECT host/port policy. 2/2 sabotages caught |
| M2.2 | DONE | 2 | evidence/M2.2/20261117T031137Z | TLS interception: per-session P-256 CA, per-host leaf LRU (4096), ALPN h2+h1 client-side, upstream verify vs system+fixture roots (TLS>=1.2), key confined to keystore. SNI/Host/:authority must EQUAL the CONNECT authority after case/trailing-dot folding (suffix, prefix, superstring, empty SNI, IP-literal+name, wrong port all denied + recorded); failed denial-record appends surface as broker errors. 3/3 sabotages caught |
| M2.3 | DONE | 2 | evidence/M2.3/20261117T031244Z | streaming both directions <= bufferLimit, on-the-fly SHA-256, flush per write (1000 SSE events distinct reads, p99 added delay <2ms), trailers preserved, client-abort cancels upstream within 1s. Byte equality 0/1/1KiB/1MiB/1MiB+1/1GiB both directions and 1GiB RSS bound use a bytes-moved stall watchdog, not a wall-clock budget (throughput is MM2.5's measured number, never asserted). request_digest covers every spec-03 input; tests perturb method/scheme/authority/path/query/body/content-type and prove default-port and authority-case normalization. 3/3 sabotages caught |
