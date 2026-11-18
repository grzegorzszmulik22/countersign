// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// RFC 8785 JSON Canonicalization Scheme (JCS), needed by spec/04 §6.3:
// SHA-256(canonical(intent.input)) == SHA-256(canonical(call.arguments)).
package reconcile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// CanonString returns the JCS canonical form of a JSON value represented
// with Go types (nil, bool, string, json.Number, float64, int64, int,
// []any, map[string]any).
func CanonString(v any) (string, error) {
	var b strings.Builder
	if err := writeCanon(&b, v); err != nil {
		return "", err
	}
	return b.String(), nil
}

// CanonSHA256 is the hex SHA-256 of the canonical form — the digest §6.3
// compares and the digest intent.declared carries as input_sha256.
func CanonSHA256(v any) (string, error) {
	s, err := CanonString(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:]), nil
}

func writeCanon(b *strings.Builder, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		writeCanonString(b, x)
	case json.Number:
		return writeCanonNumber(b, x.String())
	case float64:
		return writeCanonFloat(b, x)
	case float32:
		return writeCanonFloat(b, float64(x))
	case int:
		b.WriteString(strconv.Itoa(x))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case uint64:
		if x <= math.MaxInt64 {
			b.WriteString(strconv.FormatUint(x, 10))
		} else {
			return writeCanonFloat(b, float64(x))
		}
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanon(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		// JCS: object members are sorted by UTF-16 code units.
		sort.Slice(keys, func(i, j int) bool {
			return utf16Less(keys[i], keys[j])
		})
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeCanonString(b, k)
			b.WriteByte(':')
			if err := writeCanon(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("cannot canonicalize %T", v)
	}
	return nil
}

// utf16Less compares two strings by their UTF-16 code units (RFC 8785 §3.2.3).
func utf16Less(a, b string) bool {
	ra := []rune(a)
	rb := []rune(b)
	ca, cb := utf16.Encode(ra), utf16.Encode(rb)
	n := len(ca)
	if len(cb) < n {
		n = len(cb)
	}
	for i := 0; i < n; i++ {
		if ca[i] != cb[i] {
			return ca[i] < cb[i]
		}
	}
	return len(ca) < len(cb)
}

// writeCanonString writes a JSON string per JCS escaping rules: only the
// mandatory escapes (", \, control chars as \b \f \n \r \t or \uXXXX).
func writeCanonString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// writeCanonNumber renders a JSON number literal (from the document) per
// JCS: integer literals emit their digits directly; the rest are parsed
// as IEEE-754 doubles and emitted per ECMAScript Number::toString.
func writeCanonNumber(b *strings.Builder, lit string) error {
	if !strings.ContainsAny(lit, ".eE") {
		if n, err := strconv.ParseInt(lit, 10, 64); err == nil {
			b.WriteString(strconv.FormatInt(n, 10))
			return nil
		}
	}
	f, err := strconv.ParseFloat(lit, 64)
	if err != nil {
		return fmt.Errorf("bad number %q", lit)
	}
	return writeCanonFloat(b, f)
}

// writeCanonFloat emits a double per ECMAScript Number::toString: shortest
// round-trip digits; fixed notation for a decimal exponent in [-6, 20],
// exponential ("1e+21") outside it. "-0" is "0".
func writeCanonFloat(b *strings.Builder, f float64) error {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return fmt.Errorf("non-finite number cannot be canonicalized")
	}
	if f == 0 {
		b.WriteByte('0')
		return nil
	}
	neg := f < 0
	if neg {
		f = -f
	}
	// Shortest round-trip digits: d1.d2…dk × 10^exp10.
	digits, exp10 := shortestDigits(f)
	// adjusted = decimal exponent of the most significant digit.
	adjusted := exp10
	integral := f == math.Trunc(f)
	switch {
	case integral && adjusted < 21:
		if neg {
			b.WriteByte('-')
		}
		b.WriteString(digits)
		for i := len(digits); i <= adjusted; i++ {
			b.WriteByte('0')
		}
	case -6 <= adjusted && adjusted < 21:
		if neg {
			b.WriteByte('-')
		}
		writeFixed(b, digits, adjusted)
	default:
		if neg {
			b.WriteByte('-')
		}
		b.WriteByte(digits[0])
		if len(digits) > 1 {
			b.WriteByte('.')
			b.WriteString(digits[1:])
		}
		fmt.Fprintf(b, "e%+d", adjusted)
	}
	return nil
}

// writeFixed writes 0.digits×10^(adjusted+1) in plain decimal notation.
func writeFixed(b *strings.Builder, digits string, adjusted int) {
	if adjusted >= 0 {
		for i, c := range digits {
			if i == adjusted+1 {
				b.WriteByte('.')
			}
			b.WriteByte(byte(c))
		}
		for i := len(digits); i <= adjusted; i++ {
			b.WriteByte('0')
		}
		return
	}
	b.WriteString("0.")
	for i := -1; i > adjusted; i-- {
		b.WriteByte('0')
	}
	b.WriteString(digits)
}

// shortestDigits returns the shortest decimal digit string d1d2…dk and the
// exponent exp10 such that f = d1.d2…dk × 10^exp10 (f > 0, finite).
func shortestDigits(f float64) (string, int) {
	s := strconv.FormatFloat(f, 'e', -1, 64)
	// s looks like "1.2345e+21" or "5e-07".
	mant, expStr, _ := strings.Cut(s, "e")
	exp, err := strconv.Atoi(expStr)
	if err != nil {
		// FormatFloat always yields a valid exponent.
		panic(err)
	}
	mant = strings.Replace(mant, ".", "", 1)
	mant = strings.TrimRight(mant, "0")
	if mant == "" {
		mant = "0"
	}
	return mant, exp
}

// DecodeJSON decodes one JSON document preserving number literals as
// json.Number so canonicalization sees the original value.
func DecodeJSON(data []byte) (any, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("trailing data")
	}
	return v, nil
}
