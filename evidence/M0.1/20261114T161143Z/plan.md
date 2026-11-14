# Plan M0.1 — repository and toolchain

- Files: Makefile, .gitignore, LICENSE (Apache-2.0), go.mod (module github.com/countersign/countersign), .golangci.yml,
  tools/{versions.env,install-tools.sh,verify-versions.sh,check-license.sh,sysinfo.sh,check.sh,sabotage.sh,regress.sh},
  internal/names/{names.go,names_test.go}, repo skeleton of `02` §7 with .gitkeep, docs/toolchain.md,
  test/checks/check-M0.1.sh, test/sabotage/M0.1/{unformatted-file,missing-licence-header,unpinned-tool}.patch.
- Toolchain (check.sh/sabotage.sh/regress.sh) is built now because M0.1's own loop needs it; M0.5 adds its own proof.
- Pins (all linux/arm64, sha256-verified): go1.27.4, kind v0.33.0, kubectl v1.37.2, helm v4.3.2, golangci-lint v2.15.0,
  python 3.13.18 (python-build-standalone 20261110, install_only_stripped), cryptography 50.0.2 wheel (pinned sha256),
  kindest/node v1.37.0 digest (arm64 manifest confirmed).
- Downloads cache to ~/.cache/countersign so `make tools` in a fresh clone is offline-capable after first install.
- Checks to satisfy: C0.1.1 fresh clone `tools lint test`; C0.1.2 versions == pins; C0.1.3 porcelain clean after lint;
  C0.1.4 countersign.dev/module path only in internal/names + imports; C0.1.5 sysinfo fields.
- First test written: test/checks/check-M0.1.sh asserting all five; then the three sabotage patches; then implement.
- Note: host has no `make`; GNU Make 4.3 extracted to ~/.local (user space) — bootstrap prerequisite, not in .tools.
