# Lane progress: creds

Rows follow 06-agent-loop.md §13.

| chunk | status | attempts | last evidence folder | note |
|---|---|---|---|---|
| M3.2 | DONE | 1 | evidence/M3.2/20261117T165913Z | store (file + k8s iface), per-session placeholders, write-ahead injection; 4928/50000 injection events verified vs Python matcher; 3/3 sabotages caught; MM3.3 p50 0.0027 ms ≤ 0.3; canary scan 0 |
| M3.3 | DONE | 1 | evidence/M3.3/20261117T165914Z | pinning (cred headers + Basic decode), csph_ misuse incl. cross-session/other-grant, §4.4 shapes 100%/0% on credshapes.json; 3/3 sabotages caught |
| M3.4 | DONE | 2 | evidence/M3.4/20261117T202529Z | streaming scrubber (carry window, all split points), raw/b64/urlenc/Basic forms, headers+trailers, gzip decode, fail-closed encodings; scrubber emits zero-copy spans (no per-chunk concat), MM3.4 measured against concurrent paired legs; 3/3 sabotages caught; MM3.4 penalty 0.6% ≤ 25% (was 28.9% under regress-load with per-chunk alloc) |
| M3.5 | DONE | 1 | evidence/M3.5/20261117T165914Z | body/url/rate limits at boundary, per-(session,grant) bucket, deferred-body mid-write cap w/ result.error=limit-body, redirects not followed; 2/2 sabotages caught; fixed parseSize unit parsing + capBody at-limit |
