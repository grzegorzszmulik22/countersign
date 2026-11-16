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
export PATH="$HOME/.local/bin:$HOME/.local/usr/bin:$PATH"
cd "$(dirname "$0")/../.."
ROOT=$PWD
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
# SNAP is an immutable snapshot of the commit under test: it is the docker
# build context and the source tree the fixture binaries are built from. The
# build context must never be the live working tree — under parallel regress
# another suite writing a file mid-tar breaks `docker build`.
SNAP="$WORK/snap"
mkdir -p "$SNAP"
git archive HEAD | tar -x -C "$SNAP" || {
    for id in C0.4.1 C0.4.2 C0.4.3 C0.4.4 C0.4.image; do
        bad "$id" "git archive HEAD failed"
    done
    exit "$fail"
}
BIN=$SNAP/bin
mkdir -p "$BIN"
CADIR=$WORK/ca
SCEN=$ROOT/test/vectors/transcripts
AGENT=cs-m04-agent-$$

cleanup() {
    for c in cs-m04-mockllm-$$ cs-m04-fakehub-$$ cs-m04-echo-$$ cs-m04-mcpdemo-$$ "$AGENT"; do
        docker rm -f "$c" >/dev/null 2>&1
    done
    docker network rm "$NET" >/dev/null 2>&1
    docker volume rm "$VOL" >/dev/null 2>&1
    docker image rm -f "$IMG" >/dev/null 2>&1
}
trap cleanup EXIT

# ---------- prerequisites ----------------------------------------------------
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    skipenv C0.4.1 "no working docker on this host"
    skipenv C0.4.2 "no working docker on this host"
    skipenv C0.4.3 "no working docker on this host"
    skipenv C0.4.4 "no working docker on this host"
    skipenv C0.4.image "no working docker on this host"
    exit 0  # nothing runnable; other checks below still apply
fi

if ! ( cd "$SNAP" && "$GO" build -tags fixtures -o bin/ ./test/fixtures/cmd/... ) >"$WORK/logs/build.log" 2>&1; then
    for id in C0.4.1 C0.4.2 C0.4.3 C0.4.4 C0.4.image; do
        bad "$id" "fixture/agent build failed: $(tail -3 "$WORK/logs/build.log" | tr '\n' ' ')"
    done
    exit "$fail"
fi

if ! docker build -f "$SNAP/test/fixtures/scriptagent/Dockerfile" -t "$IMG" "$SNAP" >"$WORK/logs/docker-build.log" 2>&1; then
    for id in C0.4.1 C0.4.2 C0.4.3 C0.4.4 C0.4.image; do
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

[ "$fail" -eq 0 ] && echo "M0.4 suite: all checks passed" || echo "M0.4 suite: FAILURES" >&2
exit "$fail"
