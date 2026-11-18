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

// passThrough is the explicit allowlist of ambient variables the sandbox
// inherits verbatim. Everything else the parent exported is a potential
// credential channel — API keys, cloud credentials, agent sockets,
// kube/docker/gcloud config locations — and does not cross the boundary.
// A variable not on this list cannot smuggle credentials in; new entries
// must be innocuous by inspection.
var passThrough = map[string]bool{
	"PATH": true, "HOME": true, "USER": true, "LOGNAME": true,
	"SHELL": true, "HOSTNAME": true,
	"LANG": true, "LC_ALL": true, "LC_CTYPE": true, "LC_MESSAGES": true,
	"TERM": true, "COLORTERM": true, "TZ": true,
	"TMPDIR": true,
	"EDITOR": true, "VISUAL": true, "PAGER": true,
}

// agentSocketVars name ambient variables whose values are host agent
// sockets: channels that sign with a real credential without the key
// ever being readable. The allowlist drops the variables; coversFor
// additionally makes each named socket unreachable inside the mount
// namespace, because a unix socket is a file the netns does not hide.
var agentSocketVars = []string{
	"SSH_AUTH_SOCK", "SSH_AGENT_SOCK", "GPG_AGENT_INFO",
	"SSH_AGENT_LAUNCHER", "GCR_SSH_AGENT_SOCK",
}

// credentialFileVars name ambient variables whose values point at
// credential files or dirs outside the home list — cloud keyfiles,
// kubeconfigs, docker config. The variables are dropped by the
// allowlist; each absolute path they named is covered too, so the file
// is not merely unnamed but unreadable.
var credentialFileVars = []string{
	"GOOGLE_APPLICATION_CREDENTIALS", "AWS_SHARED_CREDENTIALS_FILE",
	"AWS_CONFIG_FILE", "AWS_WEB_IDENTITY_TOKEN_FILE",
	"KUBECONFIG", "DOCKER_CONFIG", "DOCKER_CERT_PATH",
	"AZURE_CONFIG_DIR", "CLOUDSDK_CONFIG", "NETRC",
	"GIT_CREDENTIALS", "GIT_SSH_KEY_PATH",
}

// credentialPaths are host locations that hold credentials as files.
// Inside the enforced mount namespace each existing entry is hidden:
// directories under an empty tmpfs, files and sockets under /dev/null.
// $H is the ambient home directory, $X the ambient XDG_RUNTIME_DIR.
var credentialPaths = []string{
	"$H/.ssh", "$H/.gnupg", "$H/.aws", "$H/.azure", "$H/.kube",
	"$H/.docker", "$H/.config/gcloud", "$H/.config/gh",
	"$H/.config/hub", "$H/.config/heroku", "$H/.config/doctl",
	"$H/.netrc", "$H/.git-credentials", "$H/.npmrc", "$H/.pypirc",
	"$H/.cargo/credentials", "$H/.cargo/credentials.toml",
	"$H/.gem/credentials", "$H/.docker/config.json",
	"$X/gnupg", "$X/keyring", "$X/gcr",
}

// boundaryOwned is the set of variable names the boundary sets itself;
// an ambient (or escaped CS_RUN_ENV_) name matching one is dropped.
func boundaryOwned() map[string]bool {
	owned := map[string]bool{}
	for _, v := range proxyVars {
		owned[v] = true
	}
	for _, v := range trustVars {
		owned[v] = true
	}
	for _, v := range internalVars {
		owned[v] = true
	}
	return owned
}

// proxyURL builds the proxy URL the agent's env advertises. The session
// token is the Basic password the broker checks.
func proxyURL(hostport, token string) string {
	return "http://" + url.UserPassword("cs", token).String() + "@" + hostport
}

// sandboxEnv renders the agent environment: boundary variables first
// (so getenv-first semantics can never prefer an ambient value), then
// the allowlisted ambient pass-through, then placeholders. Ambient
// duplicates of a boundary-owned name are dropped; ambient duplicates of
// an allowed name pass through in order (matching the parent's getenv
// view). NO_PROXY is deliberately empty so nothing bypasses the broker.
func sandboxEnv(ambient []string, proxy, caPath string, placeholders map[string]string) []string {
	owned := boundaryOwned()
	for name := range placeholders {
		owned[name] = true
	}

	out := make([]string, 0, len(ambient)+16)
	// Boundary variables first: with getenv returning the first match,
	// nothing ambient can shadow them even if the allowlist is widened
	// incorrectly later.
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

	for _, kv := range ambient {
		name, _, ok := strings.Cut(kv, "=")
		if !ok || owned[name] || !passThrough[name] {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// coversFor returns the host paths the mount namespace must hide for
// this ambient environment: every agent socket named by the ambient env
// (SSH/GPG/keyring agents are unix sockets — the netns does not block
// them) plus the static credential file list. home and xdg come from
// the ambient env; empty means "unset".
func coversFor(ambient []string) []string {
	env := map[string]string{}
	for _, kv := range ambient {
		if n, v, ok := strings.Cut(kv, "="); ok {
			env[n] = v
		}
	}
	var out []string
	for _, v := range agentSocketVars {
		val := env[v]
		if val == "" || !strings.HasPrefix(val, "/") {
			continue
		}
		// GPG_AGENT_INFO may be path:pid or host:port:pid — only a
		// filesystem path is coverable.
		path := val
		if i := strings.LastIndex(path, ":"); i >= 0 {
			if i+1 < len(path) && allDigits(path[i+1:]) {
				path = path[:i]
			}
		}
		if strings.HasPrefix(path, "/") {
			out = append(out, path)
		}
	}
	for _, v := range credentialFileVars {
		val := env[v]
		if val == "" {
			continue
		}
		// KUBECONFIG may carry a colon-separated path list.
		for _, p := range strings.Split(val, ":") {
			if strings.HasPrefix(p, "/") {
				out = append(out, p)
			}
		}
	}
	home, xdg := env["HOME"], env["XDG_RUNTIME_DIR"]
	for _, p := range credentialPaths {
		p = strings.ReplaceAll(p, "$H", home)
		p = strings.ReplaceAll(p, "$X", xdg)
		if strings.Contains(p, "$") || p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

func allDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}
