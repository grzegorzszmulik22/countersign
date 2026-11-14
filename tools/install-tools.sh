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

# shellcheck source=versions.env
. tools/versions.env
. tools/lib-pins.sh
pins_check_complete

mkdir -p "$TOOLS/bin" "$DIST" "$CACHE"

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
        curl -fL --retry 3 --connect-timeout 15 -o "$cfile.tmp" "$url" >&2
        mv "$cfile.tmp" "$cfile"
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

# --- cffi wheel (pinned; runtime dep of cryptography, installed --no-deps) --
if ! [ "$("$PYBIN/python3" -c 'import cffi; print(cffi.__version__)' 2>/dev/null)" = "$CFFI_VERSION" ]; then
    whl=$(fetch "$CFFI_WHEEL_URL" "$CFFI_SHA256" "$CFFI_WHEEL")
    "$PYBIN/python3" -m pip install --quiet --no-index --no-deps "$whl"
    echo "installed cffi $CFFI_VERSION"
fi

# --- cryptography wheel (pinned file + sha256) -------------------------------
if ! [ "$("$PYBIN/python3" -c 'import cryptography,sys; print(cryptography.__version__)' 2>/dev/null)" = "$CRYPTOGRAPHY_VERSION" ]; then
    whl=$(fetch "$CRYPTOGRAPHY_WHEEL_URL" "$CRYPTOGRAPHY_SHA256" "$CRYPTOGRAPHY_WHEEL")
    "$PYBIN/python3" -m pip install --quiet --no-index --no-deps "$whl"
    echo "installed cryptography $CRYPTOGRAPHY_VERSION"
fi

tools/verify-versions.sh
echo "tools: all pinned tools installed under $TOOLS"
