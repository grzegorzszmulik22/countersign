#!/usr/bin/env bash
# bench/live/run-task.sh: one live, non-gated real-agent run (07 §13, "Not gated, for behaviour").
#   run-task.sh <out dir> <policy.yaml> <prompt file> [setup script]
# Starts the fixtures (echo, sink, fakehub) on loopback, livebroker with the session policy,
# and an unmodified opencode (DeepSeek V4.1 Flash) whose traffic and whose tools' traffic go
# through the broker. Afterwards it asks each fixture what it received (its own /__observed
# log, never the broker's records) and compares that with the broker's records.
# Tooling, not product: M2.7's `cs run` replaces the environment set-up done here.
set -uo pipefail
out=$(realpath -m "$1") policy=$(realpath "$2") prompt=$(realpath "$3") setup=${4:-}
here=$(cd "$(dirname "$0")" && pwd)
BIN=${LIVE_BIN:-/tmp/live}
MODEL=${LIVE_MODEL:-opencode-go/deepseek-v4.1-flash}
mkdir -p "$out"/{fx,rec,broker,work}
cd "$out" || exit 1
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; }
trap cleanup EXIT

start() { # <name> <cmd...>: start a fixture, wait for its first output line
  local name=$1; shift
  "$@" > "fx/$name.out" 2> "fx/$name.err" & pids+=($!)
  for _ in $(seq 1 50); do [[ -s "fx/$name.out" ]] && return 0; timeout 0.2 tail -f /dev/null; done
  echo "fixture $name did not start" >&2; cat "fx/$name.err" >&2; exit 1
}
start echo "$BIN/echo.exe" -run-dir fx
start sink "$BIN/sink.exe" -run-dir fx
start fakehub "$BIN/fakehub.exe" -run-dir fx
echo_addr=$(head -1 fx/echo.out); hub_addr=$(head -1 fx/fakehub.out)
sink_addr=$(grep -m1 '^https=' fx/sink.out | cut -d= -f2)
resolve="echo.example.com=$echo_addr,httpbin.org=$echo_addr,github.com=$hub_addr,api.github.com=$hub_addr,evil.example.com=$sink_addr,sink.attacker.test=$sink_addr"

"$BIN/livebroker.exe" -policy "$policy" -records rec -out broker -resolve "$resolve" -fixture-ca fx/ca.crt > broker/live.out 2>&1 & pids+=($!)
for _ in $(seq 1 50); do [[ -s broker/proxy.url ]] && break; timeout 0.2 tail -f /dev/null; done
[[ -s broker/proxy.url ]] || { echo "broker did not start" >&2; cat broker/live.out >&2; exit 1; }
P=$(cat broker/proxy.url)
CA=$(cygpath -w "$out/broker/ca.pem")

[[ -n "$setup" ]] && (cd work && bash "$setup")

# The agent's environment: every proxy variable points at the broker, every CA variable at the
# session CA (what `cs run` will set inside its namespace). The model key goes to opencode's
# process only and is never printed or logged.
export OPENCODE_API_KEY="$(powershell.exe -NoProfile -Command "[Environment]::GetEnvironmentVariable('go_new_vps','Machine')" | tr -d '\r\n')"
start_s=$(date +%s)
(
  cd work
  export HTTPS_PROXY="$P" HTTP_PROXY="$P" https_proxy="$P" http_proxy="$P" ALL_PROXY="$P" NO_PROXY="" no_proxy=""
  export NODE_EXTRA_CA_CERTS="$CA" SSL_CERT_FILE="$CA" REQUESTS_CA_BUNDLE="$CA" CURL_CA_BUNDLE="$CA" GIT_SSL_CAINFO="$CA"
  export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=http.sslBackend GIT_CONFIG_VALUE_0=openssl
  timeout "${LIVE_TIMEOUT:-900}" opencode run "$(cat "$prompt")" -m "$MODEL" --variant "${LIVE_VARIANT:-max}" --auto --format json </dev/null > ../agent.jsonl 2> ../agent.err
  echo $? > ../agent.rc
)
unset OPENCODE_API_KEY
end_s=$(date +%s)

# Oracle: each fixture's own log, fetched directly (not through the broker).
for f in echo:$echo_addr fakehub:$hub_addr sink:$sink_addr; do
  name=${f%%:*} addr=${f#*:}
  # --ssl-no-revoke: Windows schannel cannot check revocation for the test CA; the
  # certificate is still verified against fx/ca.crt. A failed fetch is an oracle error, never "0".
  if ! curl -sf --ssl-no-revoke --cacert fx/ca.crt "https://$addr/__observed" -o "fx/$name.observed.json"; then
    echo "ORACLE ERROR: could not read $name's own log" | tee -a oracle-errors.txt >&2
    rm -f "fx/$name.observed.json"
  fi
done
printf '{"seconds": %s, "agent_rc": %s}\n' "$((end_s-start_s))" "$(cat agent.rc 2>/dev/null || echo null)" > run.json
python "$here/oracle.py" "$out" | tee oracle.txt
