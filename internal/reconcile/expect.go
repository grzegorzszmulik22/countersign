// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// spec/04 §6.2 expectation rules: instantiate the expectation of an
// intent's tool input and test whether an effect's request matches it.
//
// A rule fires only for a simple command that tokenizes with plain
// shell-word splitting and contains none of | & < > $ ` ( ) { } — anything
// else contributes no expectation and can reach at most WINDOW.
package reconcile

import (
	"regexp"
	"strconv"
	"strings"
)

var forbiddenRunes = "|&<>$`(){}"
var urlRE = regexp.MustCompile(`^https?://[^\s]+$`)

// splitSimple splits a command on &&, ||, ; and newlines, honouring
// quotes. An operator inside quotes does not split; the fragment then
// still contains the forbidden character and fails tokenize.
func splitSimple(command string) []string {
	var frags []string
	var cur strings.Builder
	var quote byte // 0, '\'' or '"'
	for i := 0; i < len(command); {
		c := command[i]
		if quote == 0 {
			if c == '"' || c == '\'' {
				quote = c
			} else if strings.HasPrefix(command[i:], "&&") || strings.HasPrefix(command[i:], "||") {
				frags = append(frags, cur.String())
				cur.Reset()
				i += 2
				continue
			} else if c == ';' || c == '\n' {
				frags = append(frags, cur.String())
				cur.Reset()
				i++
				continue
			}
		} else {
			if c == quote {
				quote = 0
			} else if c == '\\' && quote == '"' && i+1 < len(command) {
				cur.WriteByte(c)
				cur.WriteByte(command[i+1])
				i += 2
				continue
			}
		}
		cur.WriteByte(c)
		i++
	}
	frags = append(frags, cur.String())
	return frags
}

// tokenize returns the shell words of one simple-command fragment, or nil
// when the fragment contains a forbidden character or does not tokenize
// (unclosed quote, trailing backslash).
func tokenize(fragment string) []string {
	if strings.ContainsAny(fragment, forbiddenRunes) {
		return nil
	}
	argv, ok := shellWords(fragment)
	if !ok || len(argv) == 0 {
		return nil
	}
	return argv
}

// shellWords is POSIX shlex.split(posix=True): whitespace splits; single
// quotes are fully literal; double quotes preserve everything except the
// escape characters " \ $ ` and newline; a backslash outside quotes makes
// the next character literal. Unclosed constructs are an error.
func shellWords(s string) ([]string, bool) {
	var out []string
	var cur strings.Builder
	inTok := false
	flush := func() {
		if inTok {
			out = append(out, cur.String())
			cur.Reset()
			inTok = false
		}
	}
	for i := 0; i < len(s); {
		c := s[i]
		switch c {
		case ' ', '\t':
			flush()
			i++
		case '\'':
			inTok = true
			end := strings.IndexByte(s[i+1:], '\'')
			if end < 0 {
				return nil, false // No closing quotation
			}
			cur.WriteString(s[i+1 : i+1+end])
			i += end + 2
		case '"':
			inTok = true
			i++
			for {
				if i >= len(s) {
					return nil, false
				}
				c = s[i]
				if c == '"' {
					i++
					break
				}
				if c == '\\' {
					if i+1 >= len(s) {
						return nil, false
					}
					n := s[i+1]
					if n == '"' || n == '\\' || n == '$' || n == '`' || n == '\n' {
						if n != '\n' {
							cur.WriteByte(n)
						}
						i += 2
						continue
					}
					cur.WriteByte(c)
					cur.WriteByte(n)
					i += 2
					continue
				}
				cur.WriteByte(c)
				i++
			}
		case '\\':
			inTok = true
			if i+1 >= len(s) {
				return nil, false // No escaped character
			}
			cur.WriteByte(s[i+1])
			i += 2
		default:
			inTok = true
			cur.WriteByte(c)
			i++
		}
	}
	flush()
	return out, true
}

func basename(arg string) string {
	if i := strings.LastIndex(arg, "/"); i >= 0 {
		return arg[i+1:]
	}
	return arg
}

// urlish is the subset of urlsplit needed by §6.2: scheme://host[:port],
// path, query. Bad ports and unbalanced brackets mean "not a URL".
type urlish struct {
	scheme  string
	host    string // lowercased, brackets stripped
	port    int
	hasPort bool
	path    string
	query   string
}

func parseURLish(arg string) *urlish {
	if !urlRE.MatchString(arg) {
		return nil
	}
	scheme := arg[:strings.Index(arg, "://")]
	rest := arg[len(scheme)+3:]
	if i := strings.Index(rest, "#"); i >= 0 {
		rest = rest[:i]
	}
	var q string
	if i := strings.Index(rest, "?"); i >= 0 {
		q, rest = rest[i+1:], rest[:i]
	}
	var netloc, path string
	if i := strings.Index(rest, "/"); i >= 0 {
		netloc, path = rest[:i], rest[i:]
	} else {
		netloc = rest
	}
	if i := strings.LastIndex(netloc, "@"); i >= 0 {
		netloc = netloc[i+1:]
	}
	var host, portStr string
	hasPort := false
	if strings.HasPrefix(netloc, "[") {
		end := strings.Index(netloc, "]")
		if end < 0 {
			return nil
		}
		host, rest = netloc[1:end], netloc[end+1:]
		if strings.HasPrefix(rest, ":") {
			portStr = rest[1:]
			hasPort = portStr != ""
		}
	} else if i := strings.Index(netloc, ":"); i >= 0 {
		host, portStr = netloc[:i], netloc[i+1:]
		hasPort = portStr != ""
	} else {
		host = netloc
	}
	if host == "" {
		return nil
	}
	u := &urlish{scheme: scheme, host: strings.ToLower(host), path: path, query: q}
	if hasPort {
		if !isAllDigits(portStr) {
			return nil
		}
		n, _ := strconv.Atoi(portStr)
		if n > 65535 {
			return nil
		}
		u.port, u.hasPort = n, true
	}
	return u
}

// whenOK matches a rule's `when` clause against argv / tool input.
func whenOK(when map[string]any, argv []string, toolInput map[string]any) bool {
	if v, ok := when["argv0"]; ok && !inStrList(v, basename(argv[0])) {
		return false
	}
	if v, ok := when["argv0_prefix"]; ok {
		found := false
		for _, p := range asStrList(v) {
			if strings.HasPrefix(basename(argv[0]), p) {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	if v, ok := when["argv1"]; ok && (len(argv) < 2 || !inStrList(v, argv[1])) {
		return false
	}
	if v, ok := when["argv_prefix"]; ok {
		pre := asStrList(v)
		if len(argv)-1 < len(pre) {
			return false
		}
		for i, p := range pre {
			if argv[1+i] != p {
				return false
			}
		}
	}
	if v, ok := when["argv_eq"]; ok {
		eq := asStrList(v)
		if len(eq) != len(argv) {
			return false
		}
		for i := range eq {
			if eq[i] != argv[i] {
				return false
			}
		}
	}
	if v, ok := when["url_arg_count"]; ok {
		n := 0
		for _, a := range argv[1:] {
			if parseURLish(a) != nil {
				n++
			}
		}
		want, _ := jsonNum(v)
		if n != int(want) {
			return false
		}
	}
	if v, ok := when["input_has"]; ok {
		for _, k := range asStrList(v) {
			if _, present := toolInput[k]; !present {
				return false
			}
		}
	}
	return true
}

var methodFlags = []string{"-X", "--request", "--method"}

var curlDataFlags = []string{"-d", "--data", "--data-raw", "--data-binary",
	"--data-ascii", "--data-urlencode", "-F", "--form", "-T", "--upload-file",
	"--post-data", "--post-file"}

// curlMethod: method from -X/--request/--method, else POST when a data
// flag is present, else GET (spec/04 §6.2).
func curlMethod(argv []string) string {
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		for _, f := range methodFlags {
			if a == f && i+1 < len(argv) {
				return strings.ToUpper(argv[i+1])
			}
			if strings.HasPrefix(a, f+"=") {
				return strings.ToUpper(strings.SplitN(a, "=", 2)[1])
			}
			if !strings.HasPrefix(f, "--") && strings.HasPrefix(a, f) && len(a) > len(f) {
				return strings.ToUpper(a[len(f):]) // curl -XPOST
			}
		}
	}
	for _, a := range argv[1:] {
		if inStrSlice(curlDataFlags, a) {
			return "POST"
		}
		if !strings.HasPrefix(a, "--") && len(a) > 2 && a[0] == '-' &&
			(a[1] == 'd' || a[1] == 'F' || a[1] == 'T') {
			return "POST" // -dX, -F.., -T.. short forms
		}
		for _, f := range curlDataFlags {
			if strings.HasPrefix(f, "--") && strings.HasPrefix(a, f+"=") {
				return "POST"
			}
		}
	}
	return "GET"
}

// bindOne evaluates one bind expression; nil means unbound.
func bindOne(spec map[string]any, argv []string, toolInput map[string]any) any {
	switch str(mget(spec, "kind")) {
	case "first-arg-url":
		schemes := asStrList(mget(spec, "schemes"))
		if len(schemes) == 0 {
			schemes = []string{"https"}
		}
		for _, a := range argv[1:] {
			if u := parseURLish(a); u != nil && inStrSlice(schemes, u.scheme) {
				return a
			}
		}
		return nil
	case "single-url-arg":
		var urls []string
		for _, a := range argv[1:] {
			if parseURLish(a) != nil {
				urls = append(urls, a)
			}
		}
		if len(urls) == 1 {
			return urls[0]
		}
		return nil
	case "input-field":
		v := mget(toolInput, str(mget(spec, "field")))
		if v == nil {
			return mget(spec, "default")
		}
		if s, ok := v.(string); ok {
			return s
		}
		return nil
	case "literal":
		return mget(spec, "value")
	case "curl-method":
		return curlMethod(argv)
	}
	return nil
}

// ruleExpectations instantiates a rule on one simple command.
func ruleExpectations(rule map[string]any, argv []string, toolInput map[string]any) []map[string]any {
	when := mdict(rule, "when")
	checkArgv := argv
	if checkArgv == nil {
		checkArgv = []string{"_"}
	}
	if !whenOK(when, checkArgv, toolInput) {
		return nil
	}
	for _, tok := range asStrList(mget(rule, "forbid_tokens")) {
		for _, a := range argv {
			if a == tok {
				return nil
			}
		}
	}
	for _, a := range argv {
		for _, p := range asStrList(mget(rule, "forbid_prefixes")) {
			if strings.HasPrefix(a, p) {
				return nil
			}
		}
	}
	bound := map[string]any{}
	for name, sp := range mdict(rule, "bind") {
		spec, _ := sp.(map[string]any)
		v := bindOne(spec, argv, toolInput)
		if v == nil && truthy(mget(spec, "required")) {
			return nil
		}
		bound[name] = v
	}
	var out []map[string]any
	for _, ev := range asList(mget(rule, "expect")) {
		em, _ := ev.(map[string]any)
		exp := map[string]any{}
		for k, v := range em {
			if s, ok := v.(string); ok && strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
				exp[k] = bound[s[1:len(s)-1]] // nil -> unbound
			} else {
				exp[k] = v
			}
		}
		out = append(out, exp)
	}
	return out
}

// intentExpectations: all expectations one intent produces, over every
// simple command of its command field and every rule that applies to its
// class/tool.
func intentExpectations(cls, tool string, input map[string]any, commandField string, packs []map[string]any) []map[string]any {
	var out []map[string]any
	command, _ := mget(input, commandField).(string)
	for _, rule := range packs {
		when := mdict(rule, "when")
		if tcls := mget(when, "tool_class"); tcls != nil && tcls != cls {
			continue
		}
		if t, ok := when["tool"]; ok && t != tool {
			continue
		}
		if cls == "exec" {
			if command == "" {
				continue
			}
			for _, frag := range splitSimple(command) {
				argv := tokenize(frag)
				if argv == nil {
					continue
				}
				out = append(out, ruleExpectations(rule, argv, input)...)
			}
		} else {
			out = append(out, ruleExpectations(rule, nil, input)...)
		}
	}
	return out
}

func gitExpectMatch(exp map[string]any, req map[string]any, grant map[string]any) bool {
	op := gitOp(req, reqQuery(req))
	if op == nil {
		return false
	}
	want := strOr(mget(exp, "access"), "read")
	if want == "read" && op.access != "read" {
		return false // a read intent never covers a write op
	}
	url := mget(exp, "url")
	if truthy(url) {
		u := parseURLish(str(url))
		if u == nil {
			return false
		}
		var segs []string
		for _, s := range strings.Split(u.path, "/") {
			if s != "" {
				segs = append(segs, s)
			}
		}
		if len(segs) != 2 {
			return false
		}
		host, port := splitAuthority(str(mget(req, "authority")), 443)
		if normHost(host) != normHost(u.host) {
			return false
		}
		if u.hasPort && u.port != 0 && port != u.port {
			return false
		}
		return op.owner == segs[0] && gitSeg(segs[1]) == op.repo
	}
	// Unbound: any repository inside the selected grant.
	return gitGrantOK(mdict(mdict(grant, "match"), "matcher"), op)
}

func httpExpectMatch(exp map[string]any, req map[string]any) bool {
	method := mget(req, "method")
	if v := mget(exp, "methods"); v != nil && !inList(v, method) {
		return false
	}
	if v := mget(exp, "method"); v != nil && !jsonDeepEqual(method, v) {
		return false
	}
	scheme := strOr(mget(req, "scheme"), "https")
	defPort := 443
	if scheme == "http" {
		defPort = 80
	}
	host, port := splitAuthority(str(mget(req, "authority")), defPort)
	host = normHost(host)
	if v := mget(exp, "hosts"); v != nil {
		found := false
		for _, h := range asStrList(v) {
			if normHost(h) == host {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	url := mget(exp, "url")
	if truthy(url) {
		u := parseURLish(str(url))
		if u == nil {
			return false
		}
		if scheme != u.scheme {
			return false
		}
		uport := u.port
		if !u.hasPort || u.port == 0 { // u.port or default: 0 is falsy
			if u.scheme == "http" {
				uport = 80
			} else {
				uport = 443
			}
		}
		if normHost(u.host) != host || uport != port {
			return false
		}
		upath := u.path
		if upath == "" {
			upath = "/"
		}
		if pctDecodeUnres(strOr(mget(req, "path"), "/")) != pctDecodeUnres(upath) {
			return false
		}
		q := reqQuery(req)
		if u.query != "" {
			if !q.equal(u.query) {
				return false
			}
		} else if q.nonEmpty() {
			return false // "that URL" committed to no query
		}
	}
	return true
}

// expectationMatches: does one instantiated expectation match an effect's
// request?
func expectationMatches(exp map[string]any, req map[string]any, grant map[string]any) bool {
	switch str(mget(exp, "shape")) {
	case "git-smart-http":
		return gitExpectMatch(exp, req, grant)
	case "http":
		return httpExpectMatch(exp, req)
	}
	return false
}
