// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"
)

// Strict JSON per 03 §1–§2: valid RFC 8259 only, UTF-8 only, no duplicate
// object keys, no unknown fields on typed decode. The scanner below is the
// single gate all record bytes pass before any typed unmarshal runs.

const maxJSONDepth = 64

// checkJSON validates data as one complete JSON value with the strictness
// rules of 03 §2: UTF-8 input, no duplicate keys, valid string escapes
// including surrogate pairing, RFC 8259 numbers, bounded depth.
func checkJSON(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("input is not valid UTF-8")
	}
	p := &parser{d: data}
	p.ws()
	if err := p.value(0); err != nil {
		return err
	}
	p.ws()
	if p.i != len(p.d) {
		return fmt.Errorf("trailing data at byte %d", p.i)
	}
	return nil
}

type parser struct {
	d []byte
	i int
}

func (p *parser) errf(format string, args ...any) error {
	return fmt.Errorf("json: byte %d: %s", p.i, fmt.Sprintf(format, args...))
}

func (p *parser) ws() {
	for p.i < len(p.d) {
		switch p.d[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) value(depth int) error {
	if depth > maxJSONDepth {
		return p.errf("nesting deeper than %d", maxJSONDepth)
	}
	if p.i >= len(p.d) {
		return p.errf("unexpected end of input")
	}
	switch c := p.d[p.i]; {
	case c == '{':
		return p.object(depth)
	case c == '[':
		return p.array(depth)
	case c == '"':
		return p.string()
	case c == 't':
		return p.lit("true")
	case c == 'f':
		return p.lit("false")
	case c == 'n':
		return p.lit("null")
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	default:
		return p.errf("unexpected character %q", rune(c))
	}
}

func (p *parser) lit(s string) error {
	if len(p.d)-p.i < len(s) || string(p.d[p.i:p.i+len(s)]) != s {
		return p.errf("invalid literal, expected %q", s)
	}
	p.i += len(s)
	return nil
}

func (p *parser) object(depth int) error {
	p.i++ // '{'
	keys := map[string]struct{}{}
	p.ws()
	if p.i < len(p.d) && p.d[p.i] == '}' {
		p.i++
		return nil
	}
	for {
		p.ws()
		if p.i >= len(p.d) || p.d[p.i] != '"' {
			return p.errf("expected object key")
		}
		start := p.i
		if err := p.string(); err != nil {
			return err
		}
		var key string
		if err := json.Unmarshal(p.d[start:p.i], &key); err != nil {
			return p.errf("bad key: %v", err)
		}
		if _, dup := keys[key]; dup {
			return p.errf("duplicate key %q", key)
		}
		keys[key] = struct{}{}
		p.ws()
		if p.i >= len(p.d) || p.d[p.i] != ':' {
			return p.errf("expected ':'")
		}
		p.i++
		p.ws()
		if err := p.value(depth + 1); err != nil {
			return err
		}
		p.ws()
		if p.i >= len(p.d) {
			return p.errf("unterminated object")
		}
		if p.d[p.i] == '}' {
			p.i++
			return nil
		}
		if p.d[p.i] != ',' {
			return p.errf("expected ',' or '}'")
		}
		p.i++
	}
}

func (p *parser) array(depth int) error {
	p.i++ // '['
	p.ws()
	if p.i < len(p.d) && p.d[p.i] == ']' {
		p.i++
		return nil
	}
	for {
		p.ws()
		if err := p.value(depth + 1); err != nil {
			return err
		}
		p.ws()
		if p.i >= len(p.d) {
			return p.errf("unterminated array")
		}
		if p.d[p.i] == ']' {
			p.i++
			return nil
		}
		if p.d[p.i] != ',' {
			return p.errf("expected ',' or ']'")
		}
		p.i++
	}
}

func (p *parser) string() error {
	p.i++ // '"'
	for p.i < len(p.d) {
		c := p.d[p.i]
		switch {
		case c == '"':
			p.i++
			return nil
		case c == '\\':
			p.i++
			if p.i >= len(p.d) {
				return p.errf("unterminated escape")
			}
			e := p.d[p.i]
			p.i++
			switch e {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
			case 'u':
				if err := p.uEscape(); err != nil {
					return err
				}
			default:
				return p.errf("invalid escape '\\%c'", e)
			}
		case c < 0x20:
			return p.errf("unescaped control character")
		default:
			// Multi-byte UTF-8 already validated over the whole input.
			p.i++
		}
	}
	return p.errf("unterminated string")
}

// uEscape validates one \uXXXX sequence including surrogate pairing.
func (p *parser) uEscape() error {
	r, err := p.hex4()
	if err != nil {
		return err
	}
	switch {
	case r >= 0xD800 && r <= 0xDBFF:
		// High surrogate must be followed by \uDC00–\uDFFF.
		if len(p.d)-p.i < 6 || p.d[p.i] != '\\' || p.d[p.i+1] != 'u' {
			return p.errf("unpaired surrogate escape")
		}
		p.i += 2
		lo, err := p.hex4()
		if err != nil {
			return err
		}
		if lo < 0xDC00 || lo > 0xDFFF {
			return p.errf("unpaired surrogate escape")
		}
	case r >= 0xDC00 && r <= 0xDFFF:
		return p.errf("unpaired surrogate escape")
	}
	return nil
}

func (p *parser) hex4() (int, error) {
	if len(p.d)-p.i < 4 {
		return 0, p.errf("short \\u escape")
	}
	v := 0
	for _, c := range p.d[p.i : p.i+4] {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= int(c - '0')
		case c >= 'a' && c <= 'f':
			v |= int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v |= int(c-'A') + 10
		default:
			return 0, p.errf("bad hex digit %q", rune(c))
		}
	}
	p.i += 4
	return v, nil
}

func (p *parser) number() error {
	if p.d[p.i] == '-' {
		p.i++
	}
	if p.i >= len(p.d) {
		return p.errf("bad number")
	}
	if p.d[p.i] == '0' {
		p.i++
	} else if p.d[p.i] >= '1' && p.d[p.i] <= '9' {
		for p.i < len(p.d) && p.d[p.i] >= '0' && p.d[p.i] <= '9' {
			p.i++
		}
	} else {
		return p.errf("bad number")
	}
	if p.i < len(p.d) && p.d[p.i] == '.' {
		p.i++
		if p.i >= len(p.d) || p.d[p.i] < '0' || p.d[p.i] > '9' {
			return p.errf("bad number fraction")
		}
		for p.i < len(p.d) && p.d[p.i] >= '0' && p.d[p.i] <= '9' {
			p.i++
		}
	}
	if p.i < len(p.d) && (p.d[p.i] == 'e' || p.d[p.i] == 'E') {
		p.i++
		if p.i < len(p.d) && (p.d[p.i] == '+' || p.d[p.i] == '-') {
			p.i++
		}
		if p.i >= len(p.d) || p.d[p.i] < '0' || p.d[p.i] > '9' {
			return p.errf("bad number exponent")
		}
		for p.i < len(p.d) && p.d[p.i] >= '0' && p.d[p.i] <= '9' {
			p.i++
		}
	}
	return nil
}

// unmarshalStrict is the one decode path: strict JSON scan, then a typed
// decode that rejects unknown fields.
func unmarshalStrict(data []byte, v any) error {
	if err := checkJSON(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}
