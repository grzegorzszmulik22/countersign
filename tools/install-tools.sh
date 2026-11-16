#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# install-tools.sh — install the pinned toolchain of tools/versions.env into
# ./.tools/ without root (06-agent-loop.md §11). Idempotent: a tool already
# present at the pinned version is left alone. Downloads go through a shared
# cache ($CS_TOOLS_CACHE or ~/.cache/countersign/tools) so a fresh clone can
# install without network once the cache is warm. Every artifact is verified
# against its pinned sha256 before use. Fails fast if any pin is missing.
set -euo pipefail
export PATH="$HOME/.local/bin:$HOME/.local/usr/bin:$PATH"

cd "$(dirname "$0")/.."
ROOT=$PWD
TOOLS=$ROOT/.tools
DIST=$TOOLS/dist
CACHE=${CS_TOOLS_CACHE:-$HOME/.cache/countersign/tools}

# One retry on transient failure: every step below is idempotent, and on this
# shared host (sibling lanes + load spikes) a subprocess can die for reasons
# that vanish on a clean second run. A real failure (bad pin, no network,
# corrupt artifact) fails both attempts, so nothing is masked.
if [ "${CS_TOOLS_RETRY:-0}" != "1" ]; then
    export CS_TOOLS_RETRY=1
    if "$ROOT/tools/install-tools.sh"; then
        exit 0
    fi
    echo "install-tools: first attempt failed; retrying once" >&2
    exec "$ROOT/tools/install-tools.sh"
fi

# shellcheck source=versions.env
. tools/versions.env
. tools/lib-pins.sh
pins_check_complete

mkdir -p "$TOOLS/bin" "$DIST" "$CACHE"

# Serialize installs across this host: sibling lanes share $CACHE and run
# `make tools` concurrently (fresh-clone checks); an unlucky overlap could
# interleave writes to the same $name.tmp or delete a cache file mid-verify.
if command -v flock >/dev/null 2>&1; then
    exec {LOCKFD}>>"$CACHE/.install.lock"
    flock "$LOCKFD"
fi

# fetch <url> <sha256> <name> — returns the verified file path in the cache.
fetch() {
    local url=$1 sha=$2 name=$3
    local cfile="$CACHE/$name"
    if [ -f "$cfile" ] && ! echo "$sha  $cfile" | sha256sum -c --quiet 2>/dev/null; then
        echo "cached $name fails sha256; refetching" >&2
        rm -f "$cfile"
    fi
    if [ ! -f "$cfile" ]; then
        echo "download $name" >&2
        curl -fL --retry 3 --connect-timeout 15 -o "$cfile.$$.tmp" "$url" >&2
        mv "$cfile.$$.tmp" "$cfile"
    fi
    echo "$sha  $cfile" | sha256sum -c --quiet || {
        echo "sha256 mismatch for $name (pinned $sha)" >&2
        return 1
    }
    printf '%s\n' "$cfile"
}

# --- Go -------------------------------------------------------------------
if ! { [ -x "$TOOLS/bin/go" ] && "$TOOLS/bin/go" version | grep -q "go${GO_VERSION} "; }; then
    tgz=$(fetch "https://dl.google.com/go/${GO_TARBALL}" "$GO_SHA256" "$GO_TARBALL")
    rm -rf "$TOOLS/go"
    mkdir -p "$TOOLS/go"
    tar -xzf "$tgz" -C "$TOOLS/go" --strip-components=1
    ln -sfn ../go/bin/go "$TOOLS/bin/go"
    ln -sfn ../go/bin/gofmt "$TOOLS/bin/gofmt"
    echo "installed go $GO_VERSION"
fi

# --- kind -----------------------------------------------------------------
if ! { [ -x "$TOOLS/bin/kind" ] && "$TOOLS/bin/kind" version | grep -q "$KIND_VERSION"; }; then
    f=$(fetch "https://github.com/kubernetes-sigs/kind/releases/download/${KIND_VERSION}/kind-linux-arm64" \
        "$KIND_SHA256" "kind-${KIND_VERSION}-linux-arm64")
    cp "$f" "$TOOLS/bin/kind"
    chmod +x "$TOOLS/bin/kind"
    echo "installed kind $KIND_VERSION"
fi

# --- kubectl ---------------------------------------------------------------
if ! { [ -x "$TOOLS/bin/kubectl" ] && "$TOOLS/bin/kubectl" version --client 2>/dev/null | grep -q "$KUBECTL_VERSION"; }; then
    f=$(fetch "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/arm64/kubectl" \
        "$KUBECTL_SHA256" "kubectl-${KUBECTL_VERSION}-linux-arm64")
    cp "$f" "$TOOLS/bin/kubectl"
    chmod +x "$TOOLS/bin/kubectl"
    echo "installed kubectl $KUBECTL_VERSION"
fi

# --- Helm ------------------------------------------------------------------
if ! { [ -x "$TOOLS/bin/helm" ] && "$TOOLS/bin/helm" version 2>/dev/null | grep -q "$HELM_VERSION"; }; then
    tgz=$(fetch "https://get.helm.sh/helm-${HELM_VERSION}-linux-arm64.tar.gz" \
        "$HELM_SHA256" "helm-${HELM_VERSION}-linux-arm64.tar.gz")
    tar -xzf "$tgz" -C "$DIST" linux-arm64/helm
    cp "$DIST/linux-arm64/helm" "$TOOLS/bin/helm"
    chmod +x "$TOOLS/bin/helm"
    echo "installed helm $HELM_VERSION"
fi

# --- golangci-lint ----------------------------------------------------------
if ! { [ -x "$TOOLS/bin/golangci-lint" ] && "$TOOLS/bin/golangci-lint" version 2>/dev/null | grep -q "${GOLANGCI_LINT_VERSION#v}"; }; then
    tgz=$(fetch "https://github.com/golangci/golangci-lint/releases/download/${GOLANGCI_LINT_VERSION}/golangci-lint-${GOLANGCI_LINT_VERSION#v}-linux-arm64.tar.gz" \
        "$GOLANGCI_LINT_SHA256" "golangci-lint-${GOLANGCI_LINT_VERSION#v}-linux-arm64.tar.gz")
    tar -xzf "$tgz" -C "$DIST"
    cp "$DIST/golangci-lint-${GOLANGCI_LINT_VERSION#v}-linux-arm64/golangci-lint" "$TOOLS/bin/golangci-lint"
    chmod +x "$TOOLS/bin/golangci-lint"
    echo "installed golangci-lint $GOLANGCI_LINT_VERSION"
fi

# --- Python (standalone build) ----------------------------------------------
if ! { [ -x "$TOOLS/python/bin/python3" ] && [ "$("$TOOLS/python/bin/python3" --version 2>/dev/null)" = "Python $PYTHON_VERSION" ]; }; then
    tgz=$(fetch "https://github.com/astral-sh/python-build-standalone/releases/download/${PYTHON_STANDALONE_BUILD}/${PYTHON_TARBALL}" \
        "$PYTHON_SHA256" "$PYTHON_TARBALL")
    rm -rf "$TOOLS/python"
    mkdir -p "$TOOLS/python"
    tar -xzf "$tgz" -C "$TOOLS/python" --strip-components=1
    echo "installed python $PYTHON_VERSION"
fi
PYBIN="$TOOLS/python/bin"
[ -x "$PYBIN/python3" ] || { echo "python install missing python3" >&2; exit 1; }
"$PYBIN/python3" -m pip --version >/dev/null 2>&1 || "$PYBIN/python3" -m ensurepip --upgrade >/dev/null 2>&1 || true
ln -sfn ../python/bin/python3 "$TOOLS/bin/python3"

# --- libatomic (runtime lib for the pinned node) -----------------------------
# The upstream node linux-arm64 binary links libatomic.so.1, which minimal
# hosts do not ship and which cannot be installed system-wide without root.
# The pinned deb is verified by sha256, then its .so is unpacked under
# .tools/lib — the node wrapper below puts that dir on LD_LIBRARY_PATH.
mkdir -p "$TOOLS/lib"
if ! { [ -f "$TOOLS/lib/.libatomic-version" ] && grep -qx "$LIBATOMIC_VERSION" "$TOOLS/lib/.libatomic-version"; }; then
    deb=$(fetch "$LIBATOMIC_URL" "$LIBATOMIC_SHA256" "$LIBATOMIC_DEB")
    # Extract with the pinned python (ar/binutils is not guaranteed on a
    # minimal host; tarfile handles the ar container + xz payload itself).
    "$PYBIN/python3" - "$deb" "$TOOLS/lib" <<'PYEOF'
import io, os, sys, tarfile
deb, dest = sys.argv[1], sys.argv[2]
data = open(deb, "rb").read()
assert data[:8] == b"!<arch>\n", "not an ar archive"
off, payload = 8, None
while off + 60 <= len(data):
    name = data[off:off + 16].decode().strip()
    size = int(data[off + 48:off + 58].decode().strip())
    body = data[off + 60:off + 60 + size]
    if name.startswith("data.tar"):
        payload = body
        break
    off += 60 + size + (size & 1)
assert payload is not None, "no data.tar member"
with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as tf:
    member = next(m for m in tf.getmembers() if m.name.endswith("/libatomic.so.1.2.0"))
    src = tf.extractfile(member)
    out = os.path.join(dest, "libatomic.so.1.2.0")
    with open(out, "wb") as f:
        f.write(src.read())
    os.chmod(out, 0o755)
PYEOF
    ln -sfn libatomic.so.1.2.0 "$TOOLS/lib/libatomic.so.1"
    echo "$LIBATOMIC_VERSION" > "$TOOLS/lib/.libatomic-version"
    echo "installed libatomic $LIBATOMIC_VERSION"
fi

# --- Node.js (ships npm) -----------------------------------------------------
if ! { [ -x "$TOOLS/node/bin/node" ] && \
    [ "$(env "LD_LIBRARY_PATH=$TOOLS/lib" "$TOOLS/node/bin/node" --version 2>/dev/null)" = "$NODE_VERSION" ]; }; then
    tgz=$(fetch "https://nodejs.org/dist/${NODE_VERSION}/${NODE_TARBALL}" \
        "$NODE_SHA256" "$NODE_TARBALL")
    rm -rf "$TOOLS/node"
    mkdir -p "$TOOLS/node"
    tar -xzf "$tgz" -C "$TOOLS/node" --strip-components=1
    echo "installed node $NODE_VERSION"
fi
# .tools/bin/node is a wrapper, not a symlink: it prepends .tools/lib so the
# bundled libatomic resolves even where the system lacks it. npm/npx/corepack
# stay symlinks — their env-node shebang resolves the wrapper via PATH.
# rm first: writing through an existing symlink would clobber the real binary.
rm -f "$TOOLS/bin/node"
cat > "$TOOLS/bin/node" <<'EOF'
#!/bin/sh
# Pinned node with .tools/lib on LD_LIBRARY_PATH — the pinned binary links
# libatomic.so.1, which a minimal host may not provide (see versions.env).
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
export LD_LIBRARY_PATH="$here/../lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
exec "$here/../node/bin/node" "$@"
EOF
chmod +x "$TOOLS/bin/node"
for b in npm npx corepack; do
    [ -e "$TOOLS/node/bin/$b" ] && ln -sfn "../node/bin/$b" "$TOOLS/bin/$b"
done

# --- cryptography wheel (pinned file + sha256) -------------------------------
# cffi is a runtime dep of cryptography; it was missing until M1.2.
if ! [ "$("$PYBIN/python3" -c 'import cffi; print(cffi.__version__)' 2>/dev/null)" = "$CFFI_VERSION" ]; then
    whl=$(fetch "$CFFI_WHEEL_URL" "$CFFI_SHA256" "$CFFI_WHEEL")
    "$PYBIN/python3" -m pip install --quiet --no-index --no-deps "$whl"
    echo "installed cffi $CFFI_VERSION"
fi
if ! [ "$("$PYBIN/python3" -c 'import cryptography,sys; print(cryptography.__version__)' 2>/dev/null)" = "$CRYPTOGRAPHY_VERSION" ]; then
    whl=$(fetch "$CRYPTOGRAPHY_WHEEL_URL" "$CRYPTOGRAPHY_SHA256" "$CRYPTOGRAPHY_WHEEL")
    "$PYBIN/python3" -m pip install --quiet --no-index --no-deps "$whl"
    echo "installed cryptography $CRYPTOGRAPHY_VERSION"
fi

tools/verify-versions.sh
echo "tools: all pinned tools installed under $TOOLS"
