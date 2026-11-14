// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

// scriptagent is the scripted agent (M0.4): a minimal model-driven tool-use
// loop for test sandboxes. It honours standard proxy/CA environment
// variables only; flags supply everything else.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/countersign/countersign/test/fixtures/scriptagent"
)

func main() {
	var o scriptagent.Options
	flag.StringVar(&o.API, "api", "anthropic", "model API shape: anthropic|openai-responses|openai-chat")
	flag.StringVar(&o.ModelURL, "model-url", "", "model endpoint base URL (required)")
	flag.StringVar(&o.Model, "model", "fixture-model-1", "model id")
	flag.StringVar(&o.Prompt, "prompt", "", "task prompt (required)")
	flag.StringVar(&o.MCPURL, "mcp-url", "", "MCP server Streamable HTTP endpoint")
	flag.StringVar(&o.MCPName, "mcp-name", "demo", "MCP server label in advertised tool names")
	flag.BoolVar(&o.Stream, "stream", false, "request streaming responses")
	flag.IntVar(&o.MaxTurns, "max-turns", 25, "model round-trip cap")
	flag.BoolVar(&o.Subagent, "subagent", false, "run a second conversation concurrently")
	flag.StringVar(&o.SubPrompt, "sub-prompt", "", "subagent prompt (default: same as --prompt)")
	flag.StringVar(&o.SubModelURL, "sub-model-url", "", "subagent endpoint (default: --model-url)")
	flag.StringVar(&o.Rogue, "rogue", "", "class-D switch: extra-effect|undeclared-mcp")
	flag.BoolVar(&o.WrapCommands, "wrap-commands", false, "run Bash commands via stdin, not argv")
	flag.StringVar(&o.WorkDir, "workdir", "", "tool working directory")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := scriptagent.Run(ctx, o); err != nil {
		fmt.Fprintln(os.Stderr, "scriptagent:", err)
		os.Exit(1)
	}
}
