// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"net/url"
	"strings"
)

// proxyVars is every environment variable the boundary controls; any
// ambient value is replaced.
var proxyVars = []string{
	"HTTP_PROXY", "http_proxy",
	"HTTPS_PROXY", "https_proxy",
	"ALL_PROXY", "all_proxy",
	"NO_PROXY", "no_proxy",
}

// trustVars point every common TLS stack at the session CA PEM.
var trustVars = []string{
	"SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE",
	"GIT_SSL_CAINFO", "CURL_CA_BUNDLE",
}

// internalVars are runner plumbing passed to the in-namespace init; they
// never reach the agent.
var internalVars = []string{"CS_INIT_CONFIG"}

// oracleVars name host credential-oracle channels that must not survive
// into the sandbox: an agent socket signs with a real key without the
// key ever being readable, which is exactly the "no real credential"
// property the boundary promises.
var oracleVars = []string{"SSH_AUTH_SOCK", "SSH_AGENT_PID", "GPG_AGENT_INFO"}

// proxyURL builds the proxy URL the agent's env advertises. The session
// token is the Basic password the broker checks.
func proxyURL(hostport, token string) string {
	return "http://" + url.UserPassword("cs", token).String() + "@" + hostport
}

// sandboxEnv renders the agent environment: ambient minus anything the
// boundary owns, plus proxy vars, trust vars and credential placeholders.
// NO_PROXY is deliberately empty so nothing bypasses the broker.
func sandboxEnv(ambient []string, proxy, caPath string, placeholders map[string]string) []string {
	drop := map[string]bool{}
	for _, v := range proxyVars {
		drop[v] = true
	}
	for _, v := range trustVars {
		drop[v] = true
	}
	for _, v := range internalVars {
		drop[v] = true
	}
	for _, v := range oracleVars {
		drop[v] = true
	}
	for name := range placeholders {
		drop[name] = true
	}
	out := make([]string, 0, len(ambient)+16)
	for _, kv := range ambient {
		name, _, ok := strings.Cut(kv, "=")
		if !ok || drop[name] {
			continue
		}
		out = append(out, kv)
	}
	for _, v := range proxyVars {
		if strings.HasPrefix(v, "NO_") || strings.HasPrefix(v, "no_") {
			out = append(out, v+"=")
		} else {
			out = append(out, v+"="+proxy)
		}
	}
	for _, v := range trustVars {
		out = append(out, v+"="+caPath)
	}
	for name, val := range placeholders {
		out = append(out, name+"="+val)
	}
	return out
}
