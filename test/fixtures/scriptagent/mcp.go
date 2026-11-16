// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package scriptagent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// mcpRev is the MCP protocol revision spoken by the client (Streamable HTTP
// transport, stateless mode — see evidence/M0.3 upstream notes).
const mcpRev = "2026-07-28"

// mcpClient is a minimal real MCP client over Streamable HTTP: every request
// is one POST carrying JSON-RPC 2.0 with the protocol version in _meta and
// the Mcp-* request headers.
type mcpClient struct {
	url   string
	http  *http.Client
	tools []toolDef
}

func newMCPClient(url string, hc *http.Client) *mcpClient {
	return &mcpClient{url: url, http: hc}
}

// rpc sends one JSON-RPC request and returns the result object.
func (m *mcpClient) rpc(ctx context.Context, method string, params any) (json.RawMessage, error) {
	p, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": method,
		"params": json.RawMessage(p),
		"_meta": map[string]any{
			"io.modelcontextprotocol/protocolVersion":    mcpRev,
			"io.modelcontextprotocol/clientCapabilities": map[string]any{},
		},
	})
	res, rb, err := doHTTP(ctx, m.http, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.url, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("MCP-Protocol-Version", mcpRev)
		req.Header.Set("Mcp-Method", method)
		if method == "tools/call" {
			var pm struct {
				Name string `json:"name"`
			}
			if json.Unmarshal(p, &pm) == nil && pm.Name != "" {
				req.Header.Set("Mcp-Name", pm.Name)
			}
		}
		return req, nil
	})
	if err != nil {
		return nil, err
	}
	_ = res
	var v struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rb, &v); err != nil {
		return nil, fmt.Errorf("mcp %s: bad response: %w", method, err)
	}
	if v.Error != nil {
		return nil, fmt.Errorf("mcp %s: error %d: %s", method, v.Error.Code, v.Error.Message)
	}
	return v.Result, nil
}

// init performs server/discover and tools/list, caching the tool list.
func (m *mcpClient) init(ctx context.Context) error {
	if _, err := m.rpc(ctx, "server/discover", map[string]any{}); err != nil {
		return fmt.Errorf("server/discover: %w", err)
	}
	res, err := m.rpc(ctx, "tools/list", map[string]any{})
	if err != nil {
		return fmt.Errorf("tools/list: %w", err)
	}
	var v struct {
		Tools []struct {
			Name        string         `json:"name"`
			Description string         `json:"description"`
			InputSchema map[string]any `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(res, &v); err != nil {
		return fmt.Errorf("tools/list: %w", err)
	}
	for _, t := range v.Tools {
		m.tools = append(m.tools, toolDef{Name: t.Name, Description: t.Description, Schema: t.InputSchema})
	}
	return nil
}

// call issues one tools/call and returns the flattened text content.
func (m *mcpClient) call(ctx context.Context, name string, args json.RawMessage) (string, error) {
	res, err := m.rpc(ctx, "tools/call", map[string]any{
		"name": name, "arguments": json.RawMessage(args),
	})
	if err != nil {
		return "", err
	}
	var v struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(res, &v); err != nil {
		return "", fmt.Errorf("tools/call %s: %w", name, err)
	}
	var b strings.Builder
	for _, c := range v.Content {
		if c.Type == "text" {
			b.WriteString(c.Text)
		}
	}
	if v.IsError {
		return "error: " + b.String(), nil
	}
	return b.String(), nil
}
