# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Sandbox image for the scripted agent (M0.4): a non-root userland with the
# tools an agent expects — git, curl, Python+pip, Node+npm — plus the
# scriptagent binary. linux/arm64 base pinned by digest (06 §11); the digest
# below is the ubuntu:24.04 arm64 image manifest.
FROM ubuntu:24.04@sha256:c92376659a7f14cc1f51615d73c9f4b7d8e18d59f370e02b4ed683ab4485c66c

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    git curl ca-certificates python3 python3-pip python3-venv nodejs npm \
 && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 1010 --shell /bin/bash agent \
 && mkdir -p /work && chown agent:agent /work

COPY .check-work/M0.4/bin/scriptagent /usr/local/bin/scriptagent

USER agent
WORKDIR /work

# A standard git credential helper answering from the usual GITHUB_TOKEN
# environment variable; no product-specific configuration.
RUN git config --global init.defaultBranch main \
 && git config --global user.name "Scripted Agent" \
 && git config --global user.email "agent@localhost" \
 && git config --global credential.helper \
    '!f() { echo "username=agent"; echo "password=$GITHUB_TOKEN"; }; f'

ENTRYPOINT ["/usr/local/bin/scriptagent"]
