// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	"mime"
	"strings"
)

// Endpoint identifies which model API a request path belongs to (the two
// providers spec/04 §5.1 names — no others are ever inspected).
type Endpoint int

const (
	EndpointNone Endpoint = iota
	EndpointAnthropic
	EndpointResponses
	EndpointChat
)

// EndpointForPath maps a request path to its provider endpoint. Anything
// outside the three pinned paths is not inference traffic.
func EndpointForPath(path string) Endpoint {
	switch path {
	case "/v1/messages":
		return EndpointAnthropic
	case "/v1/responses":
		return EndpointResponses
	case "/v1/chat/completions":
		return EndpointChat
	}
	return EndpointNone
}

// Provider returns the record's provider value for an endpoint.
func (e Endpoint) Provider() string {
	switch e {
	case EndpointAnthropic:
		return ProviderAnthropic
	case EndpointResponses, EndpointChat:
		return "openai"
	}
	return ""
}

// NewResponseParser selects the parser for an endpoint by the response's
// declared format: text/event-stream bodies stream events, JSON bodies
// are scanned element-wise. ok=false means the body shape is not model
// output this endpoint produces (e.g. an HTML error page).
func NewResponseParser(e Endpoint, contentType string) (ResponseParser, bool) {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mt = strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	}
	sse := mt == "text/event-stream"
	json := mt == "application/json" || strings.HasSuffix(mt, "+json")
	if !sse && !json {
		return nil, false
	}
	switch e {
	case EndpointAnthropic:
		return newAnthropicParser(sse), true
	case EndpointResponses:
		return newResponsesParser(sse), true
	case EndpointChat:
		return newChatParser(sse), true
	}
	return nil, false
}
