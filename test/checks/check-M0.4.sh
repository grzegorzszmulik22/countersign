#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Check suite for chunk M0.4 (scripted agent).
# Emits one "CHECK <id> PASS|FAIL|SKIPPED-ENV" line per check; exits non-zero
# if any check fails.
#
# Topology (this host has Docker, no cluster): fixture binaries run inside
# the sandbox image on a dedicated docker network under their realistic host
# names (--network-alias); scriptagent runs in the sandbox image as the
# non-root agent user, trusting the shared test CA via standard CA env vars.
set -u
cd "$(dirname "$0")/../.."
ROOT=$PWD
export PATH="$ROOT/.tools/bin:$HOME/.local/bin:$HOME/.local/usr/bin:$PATH"
GO="$ROOT/.tools/bin/go"
PY="$ROOT/.tools/bin/python3"
MAKE=${MAKE:-make}
fail=0

say() { printf 'CHECK %s %s%s\n' "$1" "$2" "${3:+ — $3}"; }
pass() { say "$1" PASS; }
bad() { say "$1" FAIL "$2"; fail=1; }
skipenv() { say "$1" SKIPPED-ENV "$2"; }

# Per-run work dir and image tag: parallel invocations (e.g. make regress
# re-running M0.4 alongside another lane's check, or the sabotage scratch
# building the patched agent) must not share daemon-global or worktree
# state. Image tags, networks, volumes and container names are all
# PID-scoped and removed on cleanup.
WORK="$ROOT/.check-work/M0.4-$$"
rm -rf "$WORK"
mkdir -p "$WORK/ca" "$WORK/obs" "$WORK/logs"

IMG=cs-sandbox-m04:run-$$
NET=cs-m04-net-$$
VOL=cs-m04-work-$$
SNAP="$WORK/snap"
BIN=$SNAP/bin
CADIR=$WORK/ca
SCEN=$SNAP/test/vectors/transcripts
AGENT=cs-m04-agent-$$
WPROB="$WORK/wprobe"
SCR="$WORK/scrrepo"
SCRO="$WORK/scrsnap"
SCR2="$WORK/postrepo"
SCRO2="$WORK/postsnap"

# ---------- pre-run worktree state ------------------------------------------
# tree.restored (emitted by the EXIT trap, before this script's exit status is
# returned) proves the suite leaves the worktree exactly as it found it: no
# tracked-file drift, no new or missing untracked files, and the per-run work
# dir removed. The pre-* record is taken BEFORE any suite write to the live
# tree and compared after cleanup has restored the snapshot probes below.
# The snap-* record (taken right before the snapshot, below) is the reference
# for snap.fidelity.
#
# Untracked lines under evidence/ and .lane/ are excluded from the drift
# comparison: under `make regress` other suites legitimately create their own
# evidence/<chunk>/<ts>/ dirs while this suite runs, and .lane/ verify logs
# grow concurrently. Everything else must compare equal.
record_state() { # out-stem — capture status + ls-files + content hashes
    local s=$1 f
    git status --porcelain -z -uall >"$s-status.z" 2>/dev/null || : >"$s-status.z"
    tr '\0' '\n' <"$s-status.z" \
        | grep -vE '^\?\? (evidence/|\.lane/)' >"$s-status-f.txt" || :
    tr '\0' '\n' <"$s-status.z" | sed -n 's/^?? //p' >"$s-untracked.txt" || :
    git ls-files >"$s-files.txt" 2>/dev/null || : >"$s-files.txt"
    # Tracked files missing from the worktree are absent from the manifest;
    # snap.fidelity asserts they are absent in SNAP too.
    git ls-files -z | xargs -0r sha256sum >"$s-hashes.txt" 2>/dev/null || :
    # Volatile untracked dirs (other suites' evidence/, .lane/ logs) are only
    # asserted present in SNAP — their content legitimately changes between
    # hashing and add -A.
    grep -vE '^(evidence/|\.lane/)' "$s-untracked.txt" >"$s-uh-src.txt" || :
    : >"$s-uhashes.txt"
    while IFS= read -r f; do
        [ -f "$f" ] && [ ! -L "$f" ] && sha256sum "$f" >>"$s-uhashes.txt"
    done <"$s-uh-src.txt" 2>/dev/null
}
record_state "$WORK/pre"

treecheck() {
    local tfail=0 tmsg=""
    record_state "$WORK/post"
    if ! diff -q "$WORK/pre-status-f.txt" "$WORK/post-status-f.txt" >/dev/null; then
        tfail=1
        tmsg="worktree drifted: $(diff "$WORK/pre-status-f.txt" "$WORK/post-status-f.txt" | head -6 | tr '\n' '|')"
    fi
    if ! cmp -s "$WORK/pre-hashes.txt" "$WORK/post-hashes.txt"; then
        tfail=1; tmsg="${tmsg:+$tmsg }tracked file content changed"
    fi
    rm -rf "$WORK"
    [ -d "$WORK" ] && { tfail=1; tmsg="${tmsg:+$tmsg }per-run dir left: $WORK"; }
    if [ "$tfail" -eq 0 ]; then pass tree.restored; else bad tree.restored "$tmsg"; fi
    return "$tfail"
}

cleanup() {
    local rc=$?
    rm -f "$WPROB/.run" 2>/dev/null
    [ -n "${wprobpid:-}" ] && { kill "$wprobpid" 2>/dev/null; wait "$wprobpid" 2>/dev/null; }
    for c in cs-m04-mockllm-$$ cs-m04-fakehub-$$ cs-m04-echo-$$ cs-m04-mcpdemo-$$ "$AGENT"; do
        docker rm -f "$c" >/dev/null 2>&1
    done
    docker network rm "$NET" >/dev/null 2>&1
    docker volume rm "$VOL" >/dev/null 2>&1
    docker image rm -f "$IMG" >/dev/null 2>&1
    # The suite never writes to the live tree: every probe goes into the
    # snapshot (post-capture) or a scratch copy under $WORK. treecheck still
    # proves it — against bugs here, against sabotage that adds a live-tree
    # write, and against the per-run work dir surviving.
    rm -rf "$WPROB"
    treecheck
    local trc=$?
    [ "$rc" -ne 0 ] && exit "$rc"
    exit "$trc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ---------- snapshot of the working tree under test ---------------------------
# Round-4 property: this suite never writes to the live tree — not its probes,
# not debris. A parallel suite (or an inner offline loop under make regress)
# that reads the live tree while this suite runs must see exactly what it saw
# before; tree.restored proves the invariant at exit.
#
# The live->snap->image chain is therefore verified in two halves: snap.capture
# (below) and snap.fidelity prove that mksnap captures the tree exactly as it
# stands — committed content, uncommitted edits, untracked files, ignored
# files excluded — and the snap.uncommitted/snap.untracked checks then prove
# that marker content injected into the immutable snapshot after it is taken
# reaches the image and the fixture binaries. Marker edits and the
# post-snapshot probe run against the snapshot or a scratch copy under $WORK,
# never the live tree.
# check-M0.4 tests exactly the working tree it is run in — uncommitted edits
# and untracked, non-ignored files included; ignored files (.check-work,
# .tools, bin/, __pycache__) excluded. ONE immutable snapshot is taken now:
# mksnap() captures on-disk content via a temporary git index (git add -A
# honours .gitignore, records deletions, includes untracked files), write-tree
# freezes it, and git archive extracts it. Nothing written to the live tree
# afterwards can change the image or the fixture binaries, and the docker
# build context is never the live tree — under parallel regress another suite
# writing a file mid-tar breaks `docker build`.
mksnap() { # repo index-dir-stem outdir
    local repo=$1 idx=$2 out=$3 tree
    mkdir -p "$out" || return 1
    GIT_INDEX_FILE="$idx" git -C "$repo" add -A || { rm -f "$idx"; return 1; }
    tree=$(GIT_INDEX_FILE="$idx" git -C "$repo" write-tree) || { rm -f "$idx"; return 1; }
    rm -f "$idx"
    git -C "$repo" archive "$tree" | tar -x -C "$out"
}

# snap.capture: exercise mksnap() on a scratch repo seeded with every worktree
# state the real snapshot must handle — an uncommitted tracked edit, an
# untracked file, an ignored file and a .check-work dir — then prove the
# snapshot is frozen by writing more afterwards. This catches snapshot
# sabotage (e.g. archiving HEAD, or add -u dropping untracked files) even when
# the real tree happens to be clean.
csnap_capture() {
    rm -rf "$SCR" "$SCRO"; mkdir -p "$SCR"
    git init -q "$SCR" || { echo "scratch git init failed"; return 1; }
    printf 'ignored/\n.check-work/\n' >"$SCR/.gitignore"
    printf 'v1\n' >"$SCR/tracked.txt"
    git -C "$SCR" add .gitignore tracked.txt >/dev/null 2>&1 \
        && git -C "$SCR" -c user.name=m04 -c user.email=m04@m04 \
            commit -qm base >/dev/null 2>&1 || { echo "scratch seed commit failed"; return 1; }
    printf 'v2\n' >>"$SCR/tracked.txt"
    printf 'u\n' >"$SCR/untracked.txt"
    mkdir -p "$SCR/ignored" "$SCR/.check-work"
    printf 'i\n' >"$SCR/ignored/skip.txt" && printf 'c\n' >"$SCR/.check-work/cw.txt"
    mksnap "$SCR" "$WORK/scr-index" "$SCRO" || { echo "scratch snapshot failed"; return 1; }
    local rc=0
    grep -q 'v2' "$SCRO/tracked.txt" 2>/dev/null || { echo "uncommitted tracked edit missing from snapshot"; rc=1; }
    [ -f "$SCRO/untracked.txt" ] || { echo "untracked file missing from snapshot"; rc=1; }
    [ ! -e "$SCRO/ignored/skip.txt" ] || { echo "ignored file leaked into snapshot"; rc=1; }
    [ ! -e "$SCRO/.check-work" ] || { echo ".check-work leaked into snapshot"; rc=1; }
    printf 'v3\n' >>"$SCR/tracked.txt" && printf 'l\n' >"$SCR/late.txt"
    ! grep -q 'v3' "$SCRO/tracked.txt" 2>/dev/null || { echo "post-snapshot edit leaked into snapshot"; rc=1; }
    [ ! -e "$SCRO/late.txt" ] || { echo "post-snapshot file leaked into snapshot"; rc=1; }
    return "$rc"
}
if out=$(csnap_capture); then
    pass snap.capture
else
    bad snap.capture "$out"
fi

mkdir -p "$SNAP" "$BIN"
snapfail() {
    for id in C0.4.1 C0.4.2 C0.4.3 C0.4.4 C0.4.image snap.fidelity; do
        bad "$id" "$1"
    done
    exit "$fail"
}
# snap.fidelity's reference: the worktree at the instant it is snapshotted
# (the suite's own pre-snapshot probes are already in place and must be in
# SNAP; nothing written after this record can be expected there).
record_state "$WORK/snap"
if ! mksnap "$ROOT" "$WORK/snap-index" "$SNAP" >"$WORK/logs/snapshot.log" 2>&1; then
    snapfail "worktree snapshot failed: $(tail -3 "$WORK/logs/snapshot.log" | tr '\n' ' ')"
fi

# snap.fidelity: SNAP must equal the worktree as recorded at suite start —
# every tracked file identical (or absent iff it was already deleted), and
# every untracked non-ignored file captured with identical content. Compared
# against the recorded pre-state, not the live tree, so writes made after the
# snapshot — this suite's own post-probes or other suites' files — cannot
# produce a false verdict.
csnap_fidelity() {
    local rc=0 p h
    while IFS= read -r line; do
        h=${line%% *}; p=${line#*  }
        if [ ! -f "$SNAP/$p" ]; then
            echo "tracked $p missing from snapshot"; rc=1
        elif [ "$(sha256sum "$SNAP/$p" | cut -d' ' -f1)" != "$h" ]; then
            echo "tracked $p differs in snapshot"; rc=1
        fi
    done <"$WORK/snap-hashes.txt"
    while IFS= read -r p; do
        if [ -L "$p" ]; then
            # tracked symlinks are not hashed; assert the link is mirrored
            [ -L "$SNAP/$p" ] && [ "$(readlink "$SNAP/$p")" = "$(readlink "$p")" ] \
                || { echo "tracked symlink $p not mirrored in snapshot"; rc=1; }
        elif [ ! -e "$p" ]; then
            [ -e "$SNAP/$p" ] || [ -L "$SNAP/$p" ] \
                && { echo "worktree-deleted $p present in snapshot"; rc=1; }
        fi
    done <"$WORK/snap-files.txt"
    while IFS= read -r line; do
        h=${line%% *}; p=${line#*  }
        if [ ! -e "$SNAP/$p" ] && [ ! -L "$SNAP/$p" ]; then
            echo "untracked $p missing from snapshot"; rc=1
        elif [ -f "$SNAP/$p" ] && [ "$(sha256sum "$SNAP/$p" | cut -d' ' -f1)" != "$h" ]; then
            echo "untracked $p differs in snapshot"; rc=1
        fi
    done <"$WORK/snap-uhashes.txt"
    # Volatile untracked dirs (foreign evidence writes, verify logs) can grow
    # between hashing and add -A: assert capture-by-existence only.
    while IFS= read -r p; do
        [ -e "$SNAP/$p" ] || [ -L "$SNAP/$p" ] \
            || { echo "untracked $p missing from snapshot"; rc=1; }
    done < <(grep -E '^(evidence/|\.lane/)' "$WORK/snap-untracked.txt")
    return "$rc"
}
if out=$(csnap_fidelity); then
    pass snap.fidelity
else
    bad snap.fidelity "$out"
fi

# ---------- marker injection into the immutable snapshot ----------------------
# snap.fidelity just proved SNAP == the live tree byte-for-byte at snapshot
# time. Marker content written into SNAP now therefore exercises the same
# build path an uncommitted live-tree edit would have taken (snap.capture +
# snap.fidelity cover the live->snap half), while the live tree stays
# untouched. Markers are PID-scoped and inert: init() bodies fire only when
# their private env var is set, so the agent under test is unaffected during
# C0.4.x.
#
# Injected "uncommitted" edits: append an init() to the snapshot's agent.go
# and a RUN line to the snapshot's sandbox Dockerfile.
cat >>"$SNAP/test/fixtures/scriptagent/agent.go" <<EOF

// initM04SnapEdited is a check-M0.4 snapshot probe: marker content that
// reached the image under test only because it was in the snapshot.
func init() {
	if v := os.Getenv("M04SNAP_EDITED_$$"); v != "" {
		_, _ = fmt.Fprintf(os.Stderr, "M04SNAP_EDITED_$$=%s %s\n", v, m04SnapNewfile())
	}
}
EOF
printf 'RUN echo %s > /home/agent/m04snap-uncomm\n' "'M04SNAP-UNCOMM-$$'" >>"$SNAP/test/fixtures/scriptagent/Dockerfile"
# Injected "untracked" file: a new source file the fixtures build needs —
# the probe init calls m04SnapNewfile(), so dropping this file breaks the
# build, and its init() marker must run inside the image.
cat >"$SNAP/test/fixtures/scriptagent/zz_m04snap_$$.go" <<EOF
// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package scriptagent

import (
	"fmt"
	"os"
)

// m04SnapNewfile is a check-M0.4 snapshot probe defined in a file that
// exists only in the snapshot; agent.go's probe init calls it.
func m04SnapNewfile() string { return "m04snap-newfile-$$" }

func init() {
	if v := os.Getenv("M04SNAP_NEWFILE_$$"); v != "" {
		_, _ = fmt.Fprintf(os.Stderr, "M04SNAP_NEWFILE_$$=%s\n", v)
	}
}
EOF

# ---------- prerequisites ----------------------------------------------------
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    skipenv C0.4.1 "no working docker on this host"
    skipenv C0.4.2 "no working docker on this host"
    skipenv C0.4.3 "no working docker on this host"
    skipenv C0.4.4 "no working docker on this host"
    skipenv C0.4.image "no working docker on this host"
    skipenv snap.uncommitted "no working docker on this host"
    skipenv snap.untracked "no working docker on this host"
    skipenv snap.post-snapshot "no working docker on this host"
    skipenv snap.concurrent "no working docker on this host"
    exit 0  # nothing runnable; other checks below still apply
fi

# Concurrent writer: for the whole fixture+image build window a background
# loop creates, appends to, renames, replaces and deletes files in a scratch
# dir inside the work dir — a sibling of the build context, churning the same
# filesystem. With a live-tree build context this is precisely what breaks
# `docker build` mid-tar (WPROB sits inside the context then); against the
# immutable snapshot it must be harmless.
mkdir -p "$WPROB/bin"
: >"$WPROB/.run"
(
    i=0
    while [ -f "$WPROB/.run" ]; do
        i=$((i + 1))
        f="$WPROB/f$((i % 7))"
        printf 'w%s\n' "$i" >>"$f" 2>/dev/null
        mv -f "$f" "$f.moving" 2>/dev/null
        printf 'w%s\n' "$i" >"$WPROB/n$i" 2>/dev/null
        rm -f "$f.moving" "$WPROB/n$((i - 4))" 2>/dev/null
        head -c 65536 /dev/urandom >"$WPROB/bin/scriptagent" 2>/dev/null
    done
    printf '%s\n' "$i" >"$WPROB/.count"
) &
wprobpid=$!

if ! ( cd "$SNAP" && "$GO" build -tags fixtures -o bin/ ./test/fixtures/cmd/... ) >"$WORK/logs/build.log" 2>&1; then
    rm -f "$WPROB/.run"; wait "$wprobpid" 2>/dev/null
    for id in C0.4.1 C0.4.2 C0.4.3 C0.4.4 C0.4.image; do
        bad "$id" "fixture/agent build failed: $(tail -3 "$WORK/logs/build.log" | tr '\n' ' ')"
    done
    exit "$fail"
fi

docker build -f "$SNAP/test/fixtures/scriptagent/Dockerfile" -t "$IMG" "$SNAP" >"$WORK/logs/docker-build.log" 2>&1
docker_build_rc=$?
rm -f "$WPROB/.run"; wait "$wprobpid" 2>/dev/null
wprob_writes=$(cat "$WPROB/.count" 2>/dev/null || echo 0)
if [ "$docker_build_rc" -ne 0 ]; then
    for id in C0.4.1 C0.4.2 C0.4.3 C0.4.4 C0.4.image snap.concurrent; do
        bad "$id" "sandbox image build failed: $(tail -5 "$WORK/logs/docker-build.log" | tr '\n' ' ')"
    done
    exit "$fail"
fi

# ---------- shared test CA (EnsureCA semantics via the fixture binary) --------
"$BIN/echo" -addr 127.0.0.1:0 -run-dir "$CADIR" >"$WORK/logs/ca-init.log" 2>&1 &
capid=$!
for _ in $(seq 1 50); do
    [ -s "$CADIR/ca.crt" ] && [ -s "$CADIR/ca.key" ] && break
    sleep 0.1
done
kill "$capid" 2>/dev/null; wait "$capid" 2>/dev/null
if [ ! -s "$CADIR/ca.crt" ] || [ ! -s "$CADIR/ca.key" ]; then
    for id in C0.4.1 C0.4.2 C0.4.3 C0.4.4; do
        bad "$id" "test CA not generated: $(cat "$WORK/logs/ca-init.log" | tr '\n' ' ')"
    done
    exit "$fail"
fi
# The throwaway CA is generated per-run; make it readable inside the
# non-root sandbox containers.
chmod 644 "$CADIR/ca.crt" "$CADIR/ca.key"

# ---------- canaries (fxlib.Canary formula) -----------------------------------
CANARY_GH=$("$PY" - <<'PY'
import hashlib
s = hashlib.sha256(b"countersign-fixture-canary:github-agent").digest()
a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
print("CANARY_" + "".join(a[b % 36] for b in s[:32]))
PY
)
CANARY_MODEL=$("$PY" - <<'PY'
import hashlib
s = hashlib.sha256(b"countersign-fixture-canary:model").digest()
a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
print("CANARY_" + "".join(a[b % 36] for b in s[:32]))
PY
)

# ---------- network + helpers --------------------------------------------------
docker network create "$NET" >/dev/null 2>&1
docker volume create "$VOL" >/dev/null 2>&1

# qurl runs curl inside the network against a fixture's TLS endpoint.
qurl() { # host path [curl args...]
    local host=$1 path=$2; shift 2
    docker run --rm --network "$NET" -v "$CADIR:/ca:ro" \
        --entrypoint /usr/bin/curl "$IMG" \
        -sf --cacert /ca/ca.crt "$@" "https://$host$path"
}

wait_state() { # host
    for _ in $(seq 1 60); do
        qurl "$1" /__state >/dev/null 2>&1 && return 0
        sleep 0.25
    done
    return 1
}

obs() { qurl "$1" /__observed; }
reset() { qurl "$1" /__reset -X POST >/dev/null; }

fixture_start() { # name aliases(comma-separated) extra-args
    local name=$1 aliases=$2 args=${3:-}
    local aa=()
    IFS=',' read -ra aa <<<"$aliases"
    local na=()
    for a in "${aa[@]}"; do na+=(--network-alias "$a"); done
    docker run -d --rm --name "cs-m04-$name-$$" --network "$NET" "${na[@]}" \
        -v "$BIN:/fixtures:ro" -v "$CADIR:/ca:ro" -v "$SCEN:/scen:ro" \
        --entrypoint /bin/sh "$IMG" \
        -c "mkdir -p /tmp/run && cp /ca/ca.crt /ca/ca.key /tmp/run/ && exec /fixtures/$name -addr 0.0.0.0:443 -run-dir /tmp/run $args" \
        >/dev/null
}

llm_start() { # transcript-file-name
    docker rm -f cs-m04-mockllm-$$ >/dev/null 2>&1
    fixture_start mockllm "api.anthropic.com,api.openai.com" "-transcript /scen/$1"
    wait_state api.anthropic.com
}

agent_start() {
    docker rm -f "$AGENT" >/dev/null 2>&1
    docker run -d --name "$AGENT" --network "$NET" \
        -v "$VOL:/work" -v "$CADIR:/ca:ro" \
        -e HOME=/home/agent \
        -e SSL_CERT_FILE=/ca/ca.crt -e GIT_SSL_CAINFO=/ca/ca.crt \
        -e NODE_EXTRA_CA_CERTS=/ca/ca.crt -e REQUESTS_CA_BUNDLE=/ca/ca.crt \
        -e CURL_CA_BUNDLE=/ca/ca.crt -e PIP_CERT=/ca/ca.crt \
        -e GITHUB_TOKEN="$CANARY_GH" \
        -e ANTHROPIC_API_KEY="$CANARY_MODEL" -e OPENAI_API_KEY="$CANARY_MODEL" \
        --entrypoint /bin/sh "$IMG" -c 'sleep 600' >/dev/null
}

# agent_run <log-base> <args...>
agent_run() {
    local base=$1; shift
    docker exec "$AGENT" scriptagent "$@" >"$base.out" 2>"$base.err"
}

# norm_obs writes normalized "fixture method host path body_sha256" lines.
norm_obs() { # outfile fixture:obsfile ...
    local out=$1; shift
    "$PY" - "$out" "$@" <<'PY'
import json, sys
out = open(sys.argv[1], "w")
for pair in sys.argv[2:]:
    name, path = pair.split(":", 1)
    for o in json.load(open(path))["observations"]:
        out.write("%s %s %s %s %s\n" % (
            name, o.get("method", "-"), o.get("host", "-"),
            o.get("path", "-"), o.get("body_sha256", "-")))
out.close()
PY
}

# ---------- fixtures up ---------------------------------------------------------
fixture_start fakehub "github.com,api.github.com"
fixture_start echo "echo.example.com,httpbin.org"
fixture_start mcpdemo "mcp.example.com" "-hub https://api.github.com -repo acme/widgets -token $CANARY_GH"

infra_ok=1
for h in api.github.com echo.example.com mcp.example.com; do
    wait_state "$h" || { infra_ok=0; echo "fixture $h not ready"; }
done

# clone the working repo once, shared via the volume
if [ "$infra_ok" -eq 1 ]; then
    if ! docker run --rm --network "$NET" -v "$VOL:/work" -v "$CADIR:/ca:ro" \
        -e HOME=/home/agent -e GIT_SSL_CAINFO=/ca/ca.crt -e GITHUB_TOKEN="$CANARY_GH" \
        --entrypoint /usr/bin/git "$IMG" \
        clone --quiet https://github.com/acme/widgets.git /work/widgets >"$WORK/logs/clone.log" 2>&1; then
        infra_ok=0
        echo "work clone failed: $(tail -3 "$WORK/logs/clone.log" | tr '\n' ' ')"
    fi
fi
if [ "$infra_ok" -ne 1 ]; then
    for id in C0.4.1 C0.4.2 C0.4.3 C0.4.4; do
        bad "$id" "fixture infra failed to come up"
    done
    exit "$fail"
fi

# ---------- C0.4.1: 3 replays → identical ordered request lists ------------------
c041() {
    llm_start reference.scenario.json || return 1
    agent_start
    local normprev="" i
    for i in 1 2 3; do
        for h in api.anthropic.com api.github.com echo.example.com mcp.example.com; do reset "$h"; done
        if ! agent_run "$WORK/logs/c041-r$i" \
            --model-url https://api.anthropic.com --model fixture-model-1 --stream \
            --prompt "Please report the hostname of this machine, check the repo status and the open issue." \
            --mcp-url https://mcp.example.com/mcp; then
            echo "replay $i exit nonzero: $(tail -4 "$WORK/logs/c041-r$i.err" | tr '\n' ' ')"
            return 1
        fi
        for pair in "anth api.anthropic.com" "hub api.github.com" "echo echo.example.com" "mcp mcp.example.com"; do
            set -- $pair
            obs "$2" >"$WORK/obs/c041-r$i-$1.json"
        done
        norm_obs "$WORK/obs/c041-r$i.norm" \
            "anth:$WORK/obs/c041-r$i-anth.json" "hub:$WORK/obs/c041-r$i-hub.json" \
            "echo:$WORK/obs/c041-r$i-echo.json" "mcp:$WORK/obs/c041-r$i-mcp.json"
        if [ -n "$normprev" ] && ! diff -q "$normprev" "$WORK/obs/c041-r$i.norm" >/dev/null; then
            echo "replay $i request list differs from previous"
            diff "$normprev" "$WORK/obs/c041-r$i.norm" | head -10
            return 1
        fi
        normprev="$WORK/obs/c041-r$i.norm"
    done
    # sanity: the expected traffic actually happened
    "$PY" - "$WORK/obs/c041-r1-anth.json" "$WORK/obs/c041-r1-hub.json" <<'PY'
import json, sys
anth = json.load(open(sys.argv[1]))["observations"]
hub = json.load(open(sys.argv[2]))["observations"]
assert len([o for o in anth if o.get("path") == "/v1/messages"]) == 3, "want 3 model turns"
assert len([o for o in hub if "/repos/acme/widgets/issues/1" in o.get("path", "")]) == 1, "want 1 hub GET"
PY
}
if out=$(c041); then
    pass C0.4.1
else
    bad C0.4.1 "$out"
fi

# ---------- C0.4.2: parallel tool calls overlap at echo --------------------------
c042() {
    llm_start m04-parallel.scenario.json || return 1
    agent_start
    for h in api.anthropic.com api.github.com echo.example.com mcp.example.com; do reset "$h"; done
    if ! agent_run "$WORK/logs/c042" \
        --model-url https://api.anthropic.com --model fixture-model-1 \
        --prompt "fetch the two parallel streams now" ; then
        echo "agent run failed: $(tail -4 "$WORK/logs/c042.err" | tr '\n' ' ')"
        return 1
    fi
    obs echo.example.com >"$WORK/obs/c042-echo.json"
    "$PY" - "$WORK/logs/c042.err" "$WORK/obs/c042-echo.json" <<'PY'
import json, re, sys
err = open(sys.argv[1]).read()
times = {}
for m in re.finditer(r"toolcall id=(\S+) name=(\S+) start_ms=(\d+) end_ms=(\d+)", err):
    times[m.group(1)] = (int(m.group(3)), int(m.group(4)))
for k in ("toolu_e1", "toolu_e2"):
    assert k in times, "missing toolcall log for %s" % k
s1, e1 = times["toolu_e1"]
s2, e2 = times["toolu_e2"]
overlap = min(e1, e2) - max(s1, s2)
assert overlap > 0, "no interval overlap (e1=%d-%d e2=%d-%d): calls ran sequentially" % (s1, e1, s2, e2)
obs = json.load(open(sys.argv[2]))["observations"]
sse = [o for o in obs if o.get("path", "").startswith("/sse")]
assert len(sse) == 2, "want 2 /sse requests at echo, got %d" % len(sse)
print("overlap_ms=%d" % overlap)
PY
}
if out=$(c042); then
    pass C0.4.2
else
    bad C0.4.2 "$out"
fi

# ---------- C0.4.3: --subagent interleaves model calls ---------------------------
c043() {
    llm_start m04-subagent.scenario.json || return 1
    agent_start
    for h in api.anthropic.com api.github.com echo.example.com mcp.example.com; do reset "$h"; done
    if ! agent_run "$WORK/logs/c043" \
        --model-url https://api.anthropic.com --model fixture-model-1 \
        --prompt "task-main: do the main work" \
        --subagent --sub-prompt "task-sub: do the sub work"; then
        echo "agent run failed: $(tail -4 "$WORK/logs/c043.err" | tr '\n' ' ')"
        return 1
    fi
    obs api.anthropic.com >"$WORK/obs/c043-anth.json"
    "$PY" - "$WORK/obs/c043-anth.json" <<'PY'
import base64, json, sys
obs = json.load(open(sys.argv[1]))["observations"]
assert len(obs) == 4, "want 4 model calls, got %d" % len(obs)
marks = ["task-main", "task-sub", "toolu_m1", "toolu_s1"]
for i, o in enumerate(obs):
    body = base64.b64decode(o.get("body_b64") or "").decode("utf-8", "replace")
    assert o.get("extra", {}).get("turn") == i, "obs %d turn=%s" % (i, o.get("extra"))
    assert marks[i] in body, "obs %d body missing %r" % (i, marks[i])
print("interleave order ok: main sub main sub across turns 0-3")
PY
}
if out=$(c043); then
    pass C0.4.3
else
    bad C0.4.3 "$out"
fi

# ---------- C0.4.4: each rogue switch adds exactly one extra request -------------
c044() {
    # undeclared-mcp: one extra tools/call beyond the declared one.
    llm_start m04-mcp.scenario.json || return 1
    agent_start
    for h in api.anthropic.com api.github.com echo.example.com mcp.example.com; do reset "$h"; done
    if ! agent_run "$WORK/logs/c044-mcp" \
        --model-url https://api.anthropic.com --model fixture-model-1 \
        --prompt "use the mcp tool now" \
        --mcp-url https://mcp.example.com/mcp --rogue=undeclared-mcp; then
        echo "undeclared-mcp run failed: $(tail -4 "$WORK/logs/c044-mcp.err" | tr '\n' ' ')"
        return 1
    fi
    obs mcp.example.com >"$WORK/obs/c044-mcp.json"
    # extra-effect: one extra credentialed request beyond the baseline replay.
    llm_start reference.scenario.json || return 1
    for h in api.anthropic.com api.github.com echo.example.com mcp.example.com; do reset "$h"; done
    if ! agent_run "$WORK/logs/c044-base" \
        --model-url https://api.anthropic.com --model fixture-model-1 \
        --prompt "Please report the hostname of this machine, check the repo status and the open issue." \
        --mcp-url https://mcp.example.com/mcp; then
        echo "baseline run failed: $(tail -3 "$WORK/logs/c044-base.err" | tr '\n' ' ')"
        return 1
    fi
    obs api.github.com >"$WORK/obs/c044-hub-base.json"
    for h in api.anthropic.com api.github.com echo.example.com mcp.example.com; do reset "$h"; done
    if ! agent_run "$WORK/logs/c044-ee" \
        --model-url https://api.anthropic.com --model fixture-model-1 \
        --prompt "Please report the hostname of this machine, check the repo status and the open issue." \
        --mcp-url https://mcp.example.com/mcp --rogue=extra-effect; then
        echo "extra-effect run failed: $(tail -4 "$WORK/logs/c044-ee.err" | tr '\n' ' ')"
        return 1
    fi
    obs api.github.com >"$WORK/obs/c044-hub-ee.json"
    "$PY" - "$WORK/obs/c044-mcp.json" "$CANARY_GH" \
        "$WORK/obs/c044-hub-base.json" "$WORK/obs/c044-hub-ee.json" <<'PY'
import base64, json, sys
mcp = json.load(open(sys.argv[1]))["observations"]
calls = [o for o in mcp if o.get("extra", {}).get("rpc") == "tools/call"]
assert len(calls) == 2, "want exactly 2 tools/call (1 declared + 1 rogue), got %d" % len(calls)
body = base64.b64decode(calls[1].get("body_b64") or "").decode()
assert "rogue-undeclared" in body, "rogue call lacks marker args: %s" % body[:200]

canary = sys.argv[2]
base = json.load(open(sys.argv[3]))["observations"]
rogue = json.load(open(sys.argv[4]))["observations"]
assert len(rogue) == len(base) + 1, "rogue run has %d requests, baseline %d" % (len(rogue), len(base))
extra = [o for o in rogue if o.get("method") == "POST" and o.get("path") == "/repos/acme/widgets/issues"]
assert len(extra) == 1, "want exactly 1 rogue credentialed POST, got %d" % len(extra)
assert extra[0].get("extra", {}).get("token") == canary, "rogue request not credentialed"
PY
}
if out=$(c044); then
    pass C0.4.4
else
    bad C0.4.4 "$out"
fi

# ---------- C0.4.5: no Countersign imports or env -------------------------------
c045() {
    local deps bad=0
    deps=$("$GO" list -tags fixtures -deps ./test/fixtures/cmd/scriptagent 2>/dev/null)
    if echo "$deps" | grep -qE 'countersign/internal/|countersign/test/fixtures/(fxlib|fxres|fxtest)'; then
        echo "agent links product/fixture packages:"
        echo "$deps" | grep -E 'countersign/internal/|countersign/test/fixtures/(fxlib|fxres|fxtest)'
        bad=1
    fi
    if grep -rn 'COUNTERSIGN_' test/fixtures/scriptagent test/fixtures/cmd/scriptagent >/dev/null 2>&1; then
        echo "agent reads COUNTERSIGN_* variables"
        grep -rn 'COUNTERSIGN_' test/fixtures/scriptagent test/fixtures/cmd/scriptagent
        bad=1
    fi
    return "$bad"
}
if out=$(c045); then
    pass C0.4.5
else
    bad C0.4.5 "$out"
fi

# ---------- sandbox image properties --------------------------------------------
c0image() {
    local arch uid
    arch=$(docker image inspect "$IMG" --format '{{.Os}}/{{.Architecture}}' 2>/dev/null)
    [ "$arch" = "linux/arm64" ] || { echo "image arch $arch != linux/arm64"; return 1; }
    uid=$(docker run --rm --entrypoint /usr/bin/id "$IMG" -u 2>/dev/null)
    [ -n "$uid" ] && [ "$uid" != "0" ] || { echo "image user uid=$uid, want non-root"; return 1; }
    docker run --rm --entrypoint /bin/sh "$IMG" -c \
        'for t in git curl python3 pip3 node npm scriptagent; do command -v $t >/dev/null || { echo "missing $t"; exit 1; }; done' \
        || return 1
}
if out=$(c0image); then
    pass C0.4.image
else
    bad C0.4.image "$out"
fi

# ---------- fixtures-tagged lint -----------------------------------------------
lintfx() {
    command -v golangci-lint >/dev/null 2>&1 || {
        echo "golangci-lint not on PATH"
        return 1
    }
    local log="$WORK/logs/lint.scriptagent.log"
    if golangci-lint run --build-tags fixtures ./test/fixtures/scriptagent/... ./test/fixtures/cmd/scriptagent/... >"$log" 2>&1; then
        return 0
    fi
    tail -8 "$log"
    return 1
}
if out=$(lintfx); then
    pass lint.scriptagent
else
    bad lint.scriptagent "$out"
fi

# ---------- snapshot-under-test ------------------------------------------------
# The suite's own worktree snapshot, verified end to end: marker content
# injected into the snapshot must be in SNAP and inside the built image; a
# write made to a scratch worktree after ITS snapshot must reach neither the
# snapshot nor a binary built from it; and the concurrent writer churning the
# filesystem through the real build window must not have broken docker build.
csnap_uncommitted() {
    grep -q "M04SNAP-UNCOMM-$$" "$SNAP/test/fixtures/scriptagent/Dockerfile" \
        || { echo "Dockerfile edit missing from snapshot"; return 1; }
    grep -q "M04SNAP_EDITED_$$" "$SNAP/test/fixtures/scriptagent/agent.go" \
        || { echo "agent.go edit missing from snapshot"; return 1; }
    docker run --rm --entrypoint /bin/cat "$IMG" /home/agent/m04snap-uncomm 2>/dev/null \
        | grep -q "M04SNAP-UNCOMM-$$" \
        || { echo "Dockerfile edit missing from image"; return 1; }
    docker run --rm -e "M04SNAP_EDITED_$$=hit" \
        --entrypoint /usr/local/bin/scriptagent "$IMG" 2>&1 \
        | grep -q "M04SNAP_EDITED_$$=hit" \
        || { echo "edited init() did not run inside image"; return 1; }
}
if out=$(csnap_uncommitted); then
    pass snap.uncommitted
else
    bad snap.uncommitted "$out"
fi

csnap_untracked() {
    [ -f "$SNAP/test/fixtures/scriptagent/zz_m04snap_$$.go" ] \
        || { echo "untracked probe file missing from snapshot"; return 1; }
    grep -aq "m04snap-newfile-$$" "$BIN/scriptagent" \
        || { echo "untracked file marker missing from fixture binary"; return 1; }
    docker run --rm -e "M04SNAP_NEWFILE_$$=hit" \
        --entrypoint /usr/local/bin/scriptagent "$IMG" 2>&1 \
        | grep -q "M04SNAP_NEWFILE_$$=hit" \
        || { echo "untracked file init() did not run inside image"; return 1; }
}
if out=$(csnap_untracked); then
    pass snap.untracked
else
    bad snap.untracked "$out"
fi

# snap.post-snapshot, run against a scratch copy: SCR2 is a scratch repo
# (under $WORK, never the live tree). SCRO2 is its mksnap snapshot. Writes
# made to the scratch worktree AFTER the snapshot must appear in neither the
# snapshot nor a binary built from it, even while a churn loop hammers the
# scratch tree through the build window.
csnap_post() {
    rm -rf "$SCR2" "$SCRO2"; mkdir -p "$SCR2"
    git init -q "$SCR2" || { echo "scratch git init failed"; return 1; }
    printf 'module m04post\n\ngo 1.27.4\n' >"$SCR2/go.mod"
    cat >"$SCR2/main.go" <<'EOF'
package main

func main() { println("M04SNAP_PRE") }
EOF
    mksnap "$SCR2" "$WORK/post-index" "$SCRO2" || { echo "scratch snapshot failed"; return 1; }
    # Post-snapshot writes into the scratch live tree:
    cat >>"$SCR2/main.go" <<EOF
func postMarker() string { return "M04SNAP-POST-$$" }
EOF
    printf 'post\n' >"$SCR2/late.txt"
    # Churn the scratch tree while building strictly from its snapshot — the
    # threat a live-tree build context cannot survive.
    : >"$WORK/.postrun"
    (
        i=0
        while [ -f "$WORK/.postrun" ]; do
            i=$((i + 1))
            printf 'c%s\n' "$i" >>"$SCR2/churn$((i % 5))"
            mv -f "$SCR2/churn$((i % 5))" "$SCR2/churn$((i % 5)).mv" 2>/dev/null
            rm -f "$SCR2/churn$((i % 5)).mv" "$SCR2/new$((i - 3))" 2>/dev/null
            printf 'n%s\n' "$i" >"$SCR2/new$i" 2>/dev/null
        done
    ) &
    local churnpid=$!
    ( cd "$SCRO2" && "$GO" build -o postbin . ) >"$WORK/logs/postbuild.log" 2>&1
    local brc=$?
    rm -f "$WORK/.postrun"; wait "$churnpid" 2>/dev/null
    [ "$brc" -eq 0 ] || { echo "scratch build failed: $(tail -3 "$WORK/logs/postbuild.log" | tr '\n' ' ')"; return 1; }
    ! grep -q "M04SNAP-POST-$$" "$SCRO2/main.go" \
        || { echo "post-snapshot edit leaked into scratch snapshot"; return 1; }
    [ ! -e "$SCRO2/late.txt" ] \
        || { echo "post-snapshot file leaked into scratch snapshot"; return 1; }
    ! grep -aq "M04SNAP-POST-$$" "$SCRO2/postbin" \
        || { echo "post-snapshot source reached scratch binary"; return 1; }
    grep -aq "M04SNAP_PRE" "$SCRO2/postbin" \
        || { echo "scratch binary missing snapshot content"; return 1; }
}
if out=$(csnap_post); then
    pass snap.post-snapshot
else
    bad snap.post-snapshot "$out"
fi

csnap_concurrent() {
    [ "$docker_build_rc" -eq 0 ] \
        || { echo "docker build failed under concurrent writes"; return 1; }
    [ "${wprob_writes:-0}" -gt 0 ] \
        || { echo "background writer produced no writes"; return 1; }
    printf 'concurrent writer active through build window (%s iterations)\n' "$wprob_writes"
}
if out=$(csnap_concurrent); then
    pass snap.concurrent
else
    bad snap.concurrent "$out"
fi

[ "$fail" -eq 0 ] && echo "M0.4 suite: all checks passed" || echo "M0.4 suite: FAILURES" >&2
exit "$fail"
