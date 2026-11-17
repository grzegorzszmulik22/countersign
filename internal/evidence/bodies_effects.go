// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package evidence

// Record bodies of 03 §4.2 — effects.

func init() {
	registerBody("effect.http", func() any { return &EffectHTTPBody{} })
	registerBody("effect.http.result", func() any { return &EffectHTTPResultBody{} })
	registerBody("effect.tunnel", func() any { return &EffectTunnelBody{} })
	registerBody("effect.tunnel.result", func() any { return &EffectTunnelResultBody{} })
	registerBody("effect.denied", func() any { return &EffectDeniedBody{} })
	registerBody("effect.exec", func() any { return &EffectExecBody{} })
	registerBody("effect.connect", func() any { return &EffectConnectBody{} })
	registerBody("observer.gap", func() any { return &ObserverGapBody{} })
}

type Client struct {
	IP   string `json:"ip" cs:"ip"`
	Port int64  `json:"port" cs:"port"`
}

// Decision is the decision block shared by effect.http and effect.tunnel.
// action ∈ allow|deny|hold|stage; requires ∈ allow|intent|review|deny (03 §4.2).
type Decision struct {
	Action      string   `json:"action" cs:"enum:allow|deny|hold|stage"`
	Reason      string   `json:"reason"`
	Requires    string   `json:"requires" cs:"enum:allow|intent|review|deny"`
	Grant       *string  `json:"grant"`
	Credentials []string `json:"credentials"`
	WouldDeny   *string  `json:"would_deny"`
}

type Attribution struct {
	Level   string   `json:"level" cs:"enum:CONTROL|EXACT|WINDOW|STANDING|NONE"`
	Intents []string `json:"intents"`
	Lineage string   `json:"lineage" cs:"enum:owned|unowned|unknown|off"`
	Owner   *string  `json:"owner"`
}

type Budget struct {
	LeakBytes uint64 `json:"leak_bytes"`
	Writes    uint64 `json:"writes"`
}

type HTTPRequest struct {
	Method       string   `json:"method"`
	Scheme       string   `json:"scheme" cs:"enum:http|https"`
	Authority    string   `json:"authority"`
	Path         string   `json:"path"`
	QuerySHA256  string   `json:"query_sha256" cs:"hex64"`
	QueryLen     uint64   `json:"query_len"`
	HeaderNames  []string `json:"header_names"`
	BodySHA256   *string  `json:"body_sha256" cs:"hex64"`
	BodyLen      *uint64  `json:"body_len"`
	BodyDeferred bool     `json:"body_deferred"`
}

type EffectHTTPBody struct {
	EffectID      string      `json:"effect_id"`
	Actor         string      `json:"actor" cs:"enum:sandbox|world"`
	Purpose       *string     `json:"purpose" cs:"enum:sync|apply|prestate|poststate|compensate|probe"`
	For           *string     `json:"for"`
	ConnID        string      `json:"conn_id"`
	Client        Client      `json:"client"`
	Request       HTTPRequest `json:"request"`
	RequestDigest *string     `json:"request_digest" cs:"hex64"`
	Class         string      `json:"class" cs:"enum:control|safe|staged|compensable|irreversible"`
	Decision      Decision    `json:"decision"`
	Attribution   Attribution `json:"attribution"`
	Taint         []string    `json:"taint"`
	Budget        Budget      `json:"budget"`
	Inspect       string      `json:"inspect" cs:"enum:none|inference|mcp"`
}

type HTTPResponse struct {
	HeaderNames []string `json:"header_names"`
	BodySHA256  string   `json:"body_sha256" cs:"hex64"`
	BodyLen     uint64   `json:"body_len"`
}

type RequestBodyRef struct {
	SHA256 string `json:"sha256" cs:"hex64"`
	Len    uint64 `json:"len"`
}

type UpstreamRef struct {
	IP         string  `json:"ip" cs:"ip"`
	Port       int64   `json:"port" cs:"port"`
	TLSVersion *string `json:"tls_version"`
	CertSHA256 *string `json:"cert_sha256" cs:"hex64"`
}

type Timing struct {
	TotalMS float64 `json:"total_ms"`
	TTFBMS  float64 `json:"ttfb_ms"`
}

type EffectHTTPResultBody struct {
	EffectID    string         `json:"effect_id"`
	ServedBy    string         `json:"served_by" cs:"enum:upstream|world|boundary|replay"`
	Status      *int64         `json:"status"`
	Response    HTTPResponse   `json:"response"`
	RequestBody RequestBodyRef `json:"request_body"`
	Upstream    *UpstreamRef   `json:"upstream"`
	Timing      Timing         `json:"timing"`
	Scrubbed    uint64         `json:"scrubbed"`
	Error       *string        `json:"error"`
}

type EffectTunnelBody struct {
	EffectID  string   `json:"effect_id"`
	Authority string   `json:"authority"`
	SNI       *string  `json:"sni"`
	Kind      string   `json:"kind" cs:"enum:passthrough|websocket"`
	Decision  Decision `json:"decision"`
}

type EffectTunnelResultBody struct {
	EffectID   string  `json:"effect_id"`
	BytesUp    uint64  `json:"bytes_up"`
	BytesDown  uint64  `json:"bytes_down"`
	DurationMS float64 `json:"duration_ms"`
	Error      *string `json:"error"`
}

type EffectDeniedBody struct {
	ConnID    string  `json:"conn_id"`
	Client    Client  `json:"client"`
	Authority *string `json:"authority"`
	Reason    string  `json:"reason"`
	Detail    string  `json:"detail"`
}

type EffectExecBody struct {
	ExecID        string   `json:"exec_id"`
	ParentExecID  *string  `json:"parent_exec_id"`
	PID           int64    `json:"pid"`
	Binary        string   `json:"binary"`
	ArgvSHA256    []string `json:"argv_sha256" cs:"hex64,max64"`
	ArgvTruncated bool     `json:"argv_truncated"`
	UID           int64    `json:"uid"`
}

type ConnectDst struct {
	IP   string `json:"ip" cs:"ip"`
	Port int64  `json:"port" cs:"port"`
}

type EffectConnectBody struct {
	ExecID  string     `json:"exec_id"`
	PID     int64      `json:"pid"`
	Dst     ConnectDst `json:"dst"`
	SrcPort int64      `json:"src_port" cs:"port"`
	Proto   string     `json:"proto" cs:"enum:tcp|udp"`
	Outcome string     `json:"outcome" cs:"enum:to-broker|blocked"`
}

type ObserverGapBody struct {
	From   uint64 `json:"from"`
	To     uint64 `json:"to"`
	Reason string `json:"reason"`
}
