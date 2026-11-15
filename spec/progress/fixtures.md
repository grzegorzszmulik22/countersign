# Lane progress: fixtures

Rows follow 06-agent-loop.md §13. Host: agent-vpc (no Docker/Podman — cluster packaging deferred to oci-free-a1 per supervisor note).

| chunk | status | attempts | last evidence folder | note |
|---|---|---|---|---|
| M0.3 | DONE | 7 | evidence/M0.3/20261115T205828Z | toolchain ships libatomic (.tools/lib) + node wrapper; tests prove .tools binaries via sys.executable/process.execPath/npm prefix; masked-libatomic run in tools.provision |
