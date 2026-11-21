// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package inspect

// jsonScanner is an incremental scanner for non-streaming JSON response
// bodies. It never materializes the whole document: it reports, for every
// array whose member name is in watch, each element's byte range and raw
// bytes as they close; and, for scalar members of the root object, the
// member name and raw value (used for "model").
//
// Element end for objects/arrays is the matching close bracket; for
// strings and literals it is the token end. Element raw bytes are the
// exact transmitted serialization (whitespace and escapes included).
type jsonScanner struct {
	watch    map[string]bool
	onElem   func(member string, raw []byte, start, end int64)
	onMember func(name string, raw []byte)
	err      error

	abs   int64
	inStr bool
	esc   bool
	stack []*jframe

	// tok captures the current string or literal token's raw bytes.
	tokOn   bool
	tokStr  bool
	tokKey  bool // string token is an object member key
	tokMem  string
	tokElem bool // token is a watched-array element
	tokBuf  []byte

	// curElem is the element capture in progress (at most one: arrays
	// inside a captured element are never watched, so captures cannot
	// nest).
	curElem *jcap
}

type jframe struct {
	isObj    bool
	key      string // member name under which this container sits (parent obj)
	valKey   string // member name whose value is being read (obj frames)
	wantKey  bool   // obj frame: next string token is a member key
	curKey   string // last decoded member key (obj frames)
	watch    bool   // array frame: report elements
	watchKey string // array frame: member name to report
	elem     *jcap  // array frame: element capture in progress
}

// jcap captures one element's raw bytes while it is in progress.
type jcap struct {
	start int64
	buf   []byte
}

func newJSONScanner(watch []string,
	onElem func(member string, raw []byte, start, end int64),
	onMember func(name string, raw []byte)) *jsonScanner {
	ws := map[string]bool{}
	for _, w := range watch {
		ws[w] = true
	}
	return &jsonScanner{watch: ws, onElem: onElem, onMember: onMember}
}

func (sc *jsonScanner) top() *jframe {
	if len(sc.stack) == 0 {
		return nil
	}
	return sc.stack[len(sc.stack)-1]
}

func (sc *jsonScanner) feed(b []byte) error {
	if sc.err != nil {
		return sc.err
	}
	for i := 0; i < len(b); i++ {
		c := b[i]
		abs := sc.abs
		sc.abs++
		if sc.inStr {
			sc.tokBuf = append(sc.tokBuf, c)
			if sc.curElem != nil {
				sc.curElem.buf = append(sc.curElem.buf, c)
			}
			if sc.esc {
				sc.esc = false
			} else if c == '\\' {
				sc.esc = true
			} else if c == '"' {
				sc.inStr = false
				sc.endToken(abs + 1)
			}
			continue
		}
		if sc.curElem != nil {
			sc.curElem.buf = append(sc.curElem.buf, c)
		}
		switch c {
		case '"':
			sc.inStr = true
			sc.tokOn, sc.tokStr = true, true
			sc.tokBuf = append(sc.tokBuf[:0], c)
			sc.beginValue(abs)
		case '{', '[':
			sc.beginContainer(c == '{', c, abs)
		case '}', ']':
			sc.endLiteral(abs) // a close bracket ends a pending scalar
			if !sc.closeContainer(c, abs) {
				return sc.fail("mismatched close bracket")
			}
		case ',':
			sc.endLiteral(abs)
			if f := sc.top(); f != nil && f.isObj {
				f.wantKey = true
			}
		case ':':
			sc.endLiteral(abs)
			if f := sc.top(); f != nil && f.isObj && !f.wantKey {
				f.valKey = f.curKey
			}
		case ' ', '\t', '\n', '\r':
			sc.endLiteral(abs)
		default:
			if !sc.tokOn {
				sc.tokOn, sc.tokStr = true, false
				sc.tokBuf = append(sc.tokBuf[:0], c)
				sc.beginValue(abs)
			} else {
				sc.tokBuf = append(sc.tokBuf, c)
			}
		}
	}
	return nil
}

// beginValue classifies a value that starts at abs (a string, literal or
// — via beginContainer — an object/array): object member key, object
// member scalar value, watched-array element, or nothing interesting.
func (sc *jsonScanner) beginValue(abs int64) {
	sc.tokKey, sc.tokElem = false, false
	sc.tokMem = ""
	f := sc.top()
	if f == nil {
		return
	}
	if f.isObj {
		if f.wantKey {
			sc.tokKey = true
			return
		}
		if f.valKey != "" {
			sc.tokMem = f.valKey
		}
		return
	}
	if f.watch && f.elem == nil {
		f.elem = &jcap{start: abs}
		sc.curElem = f.elem
		sc.tokElem = true
	}
}

// beginContainer pushes a container entered at abs; c is the open byte.
func (sc *jsonScanner) beginContainer(isObj bool, c byte, abs int64) {
	f := sc.top()
	key := ""
	if f != nil {
		if f.isObj {
			key = f.valKey
			f.valKey = ""
		} else if f.watch && f.elem == nil {
			f.elem = &jcap{start: abs, buf: []byte{c}}
			sc.curElem = f.elem
		}
	}
	nf := &jframe{isObj: isObj, key: key, wantKey: isObj}
	if !isObj && f != nil && f.isObj && sc.watch[key] {
		nf.watch = true
		nf.watchKey = key
	}
	sc.stack = append(sc.stack, nf)
	// A container beginning as a scalar-role value is handled: it is not
	// a member scalar nor a scalar element; but as an element it was just
	// captured by f.elem above. Clear token roles set by beginValue paths.
	sc.tokKey, sc.tokElem, sc.tokMem = false, false, ""
	sc.tokOn = false
	sc.tokBuf = sc.tokBuf[:0]
}

// closeContainer pops the container c closes at abs.
func (sc *jsonScanner) closeContainer(c byte, abs int64) bool {
	f := sc.top()
	if f == nil || f.isObj != (c == '}') {
		return false
	}
	sc.stack = sc.stack[:len(sc.stack)-1]
	p := sc.top()
	if p == nil {
		return true // root container closed
	}
	if p.isObj {
		p.valKey = ""
		p.wantKey = false
		return true
	}
	// The closed container was an array element of p.
	if p.watch && p.elem != nil {
		sc.emit(p.watchKey, p.elem, abs+1)
		p.elem = nil
		sc.curElem = nil
	}
	return true
}

// endToken handles a completed string token at end offset end.
func (sc *jsonScanner) endToken(end int64) {
	tok := sc.tokBuf
	sc.tokOn = false
	sc.tokBuf = sc.tokBuf[:0]
	f := sc.top()
	switch {
	case sc.tokKey && f != nil:
		f.curKey = jsonStringDecode(tok)
		f.wantKey = false
	case sc.tokElem && f != nil && f.elem != nil:
		sc.emit(f.watchKey, &jcap{start: f.elem.start, buf: tok}, end)
		f.elem = nil
		sc.curElem = nil
	case sc.tokMem != "" && f != nil && f.isObj:
		if len(sc.stack) == 1 && sc.onMember != nil {
			sc.onMember(sc.tokMem, append([]byte(nil), tok...))
		}
		f.valKey = ""
	}
}

// endLiteral terminates a literal scalar token (number/true/false/null)
// at the delimiter byte abs (which is not part of the token).
func (sc *jsonScanner) endLiteral(abs int64) {
	if !sc.tokOn || sc.tokStr {
		return
	}
	tok := sc.tokBuf
	sc.tokOn = false
	sc.tokBuf = sc.tokBuf[:0]
	f := sc.top()
	switch {
	case sc.tokElem && f != nil && f.elem != nil:
		sc.emit(f.watchKey, &jcap{start: f.elem.start, buf: tok}, abs)
		f.elem = nil
		sc.curElem = nil
	case sc.tokMem != "" && f != nil && f.isObj:
		if len(sc.stack) == 1 && sc.onMember != nil {
			sc.onMember(sc.tokMem, append([]byte(nil), tok...))
		}
		f.valKey = ""
	}
}

func (sc *jsonScanner) emit(member string, ec *jcap, end int64) {
	if sc.onElem != nil {
		sc.onElem(member, ec.buf, ec.start, end)
	}
}

func (sc *jsonScanner) fail(msg string) error {
	sc.err = parseErrf("json response: %s", msg)
	return sc.err
}

// finish reports whether the document closed cleanly.
func (sc *jsonScanner) finish() (string, bool) {
	if sc.err != nil {
		d, _ := ParseError(sc.err)
		return d, false
	}
	if sc.inStr || sc.tokOn || len(sc.stack) != 0 {
		return "json response: truncated document", false
	}
	return "", true
}

// jsonStringDecode decodes a JSON string token including its quotes.
// Keys are ASCII in these APIs; on any malformed escape the raw bytes are
// returned so the member name can never alias a watched name.
func jsonStringDecode(tok []byte) string {
	var s string
	if err := jsonUnmarshal(tok, &s); err != nil {
		return string(tok)
	}
	return s
}
