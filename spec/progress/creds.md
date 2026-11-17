# Lane progress: creds

Rows follow 06-agent-loop.md §13.

| chunk | status | attempts | last evidence folder | note |
|---|---|---|---|---|
| M3.2 | DONE | 1 | evidence/M3.2/20261117T161302Z | store (file + k8s iface), per-session placeholders, write-ahead injection; 4928/50000 injection events verified vs Python matcher; 3/3 sabotages caught; MM3.3 p50 0.0027 ms ≤ 0.3; canary scan 0 |
| M3.3 | DONE | 1 | evidence/M3.3/20261117T161318Z | pinning (cred headers + Basic decode), csph_ misuse incl. cross-session/other-grant, §4.4 shapes 100%/0% on credshapes.json; 3/3 sabotages caught |
| M3.4 | DONE | 1 | evidence/M3.4/20261117T163703Z | streaming scrubber (carry window, all split points), raw/b64/urlenc/Basic forms, headers+trailers, gzip decode, fail-closed encodings; 3/3 sabotages caught; MM3.4 penalty ~12-14% ≤ 25% |
| M3.5 | DONE | 1 | evidence/M3.5/20261117T161820Z | body/url/rate limits at boundary, per-(session,grant) bucket, deferred-body mid-write cap w/ result.error=limit-body, redirects not followed; 2/2 sabotages caught; fixed parseSize unit parsing + capBody at-limit |
