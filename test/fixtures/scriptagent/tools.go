// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package scriptagent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// httpClient builds the agent's HTTP client: the system proxy variables
// (HTTP(S)_PROXY, ALL_PROXY, NO_PROXY) plus the standard CA file variable
// SSL_CERT_FILE appended to the system pool. Nothing else is consulted.
func httpClient() *http.Client {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if f := os.Getenv("SSL_CERT_FILE"); f != "" {
		if pem, err := os.ReadFile(f); err == nil {
			pool.AppendCertsFromPEM(pem)
		}
	}
	return &http.Client{Transport: &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSClientConfig:     &tls.Config{RootCAs: pool},
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: 8,
	}}
}

// doHTTP issues req with a bounded retry on transport errors and 5xx
// statuses — the only retry logic in the agent (benchmark scenario E18:
// upstream answers 503 twice, then 200).
func doHTTP(ctx context.Context, c *http.Client, mkReq func() (*http.Request, error)) (*http.Response, []byte, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(250 * time.Millisecond):
			}
		}
		req, err := mkReq()
		if err != nil {
			return nil, nil, err
		}
		res, err := c.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
		_ = res.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if res.StatusCode >= 500 {
			lastErr = fmt.Errorf("HTTP %d: %s", res.StatusCode, trunc(string(body), 256))
			continue
		}
		return res, body, nil
	}
	return nil, nil, lastErr
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// ---------------------------------------------------------------------------
// Built-in tools
// ---------------------------------------------------------------------------

var builtinSchemas = map[string]toolDef{
	"Bash": {
		Name:        "Bash",
		Description: "Run a shell command.",
		Schema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"command": map[string]any{"type": "string"}},
			"required":   []string{"command"},
		},
	},
	"WebFetch": {
		Name:        "WebFetch",
		Description: "Fetch a URL and return the response body.",
		Schema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"url": map[string]any{"type": "string"}},
			"required":   []string{"url"},
		},
	},
	"Read": {
		Name:        "Read",
		Description: "Read a file and return its contents.",
		Schema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"file_path": map[string]any{"type": "string"}},
			"required":   []string{"file_path"},
		},
	},
	"Write": {
		Name:        "Write",
		Description: "Write content to a file.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"file_path": map[string]any{"type": "string"},
				"content":   map[string]any{"type": "string"},
			},
			"required": []string{"file_path", "content"},
		},
	},
}

func isBuiltin(name string) bool {
	_, ok := builtinSchemas[name]
	return ok
}

// execBuiltin runs one built-in tool and returns the result text.
func (c *conv) execBuiltin(ctx context.Context, call Call) string {
	var in map[string]any
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return "error: bad tool input: " + err.Error()
	}
	str := func(k string) string {
		s, _ := in[k].(string)
		return s
	}
	switch call.Name {
	case "Bash":
		return c.execBash(ctx, str("command"))
	case "Read":
		b, err := os.ReadFile(str("file_path"))
		if err != nil {
			return "error: " + err.Error()
		}
		return trunc(string(b), 200<<10)
	case "Write":
		if err := os.WriteFile(str("file_path"), []byte(str("content")), 0o644); err != nil {
			return "error: " + err.Error()
		}
		return fmt.Sprintf("wrote %d bytes to %s", len(str("content")), str("file_path"))
	case "WebFetch":
		return c.execWebFetch(ctx, str("url"))
	}
	return "error: unknown built-in tool " + call.Name
}

// execBash runs the declared command. Default: `bash -c <command>` — the
// command string rides as one argv element (the M11 process-ownership
// anchor). With --wrap-commands the text is piped to `bash -s` on stdin so
// no exec argument carries it.
func (c *conv) execBash(ctx context.Context, command string) string {
	cctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	var cmd *exec.Cmd
	if c.o.WrapCommands {
		cmd = exec.CommandContext(cctx, "bash", "-s")
		cmd.Stdin = strings.NewReader(command)
	} else {
		cmd = exec.CommandContext(cctx, "bash", "-c", command)
	}
	if c.o.WorkDir != "" {
		cmd.Dir = c.o.WorkDir
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	text := trunc(out.String(), 200<<10)
	if err != nil {
		if text != "" {
			text += "\n"
		}
		text += "exit status: " + err.Error()
	}
	return text
}

// execWebFetch GETs url. A GITHUB_TOKEN in the environment authorizes
// github.com/api.github.com requests, matching how agents present a code
// host token.
func (c *conv) execWebFetch(ctx context.Context, url string) string {
	res, body, err := doHTTP(ctx, c.http, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		if tok := os.Getenv("GITHUB_TOKEN"); tok != "" &&
			strings.HasSuffix(req.URL.Hostname(), "github.com") {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		return req, nil
	})
	if err != nil {
		return "error: " + err.Error()
	}
	return fmt.Sprintf("HTTP %d\n%s", res.StatusCode, trunc(string(body), 200<<10))
}
