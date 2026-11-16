// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// Record is the common predicate of 03 §2. Body is a typed pointer from the
// registry in bodies_*.go; Type names it.
type Record struct {
	V       int    `json:"v" cs:"const:1"`
	Type    string `json:"type"`
	ID      string `json:"id" cs:"ulid"`
	Session string `json:"session" cs:"ulid"`
	Emitter string `json:"emitter" cs:"emitter"`
	Eseq    uint64 `json:"eseq"`
	Eprev   string `json:"eprev" cs:"hex64"`
	TS      string `json:"ts" cs:"ts"`
	Body    any    `json:"body"`
}

// bodyType returns the registered body type for a record type name.
var bodyRegistry = map[string]func() any{}
var typeRegistry = map[reflect.Type]string{}

func registerBody(typeName string, ctor func() any) {
	bodyRegistry[typeName] = ctor
	t := reflect.TypeOf(ctor()).Elem()
	typeRegistry[t] = typeName
}

// Types lists every registered record type (03 §4) in sorted order.
func Types() []string {
	out := make([]string, 0, len(bodyRegistry))
	for t := range bodyRegistry {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// NewBody returns a fresh body instance for the record type.
func NewBody(typeName string) (any, bool) {
	ctor, ok := bodyRegistry[typeName]
	if !ok {
		return nil, false
	}
	return ctor(), true
}

// TypeOf returns the record type name for a body instance.
func TypeOf(body any) (string, bool) {
	t := reflect.TypeOf(body)
	if t.Kind() != reflect.Pointer {
		return "", false
	}
	name, ok := typeRegistry[t.Elem()]
	return name, ok
}

// MarshalPredicate encodes a record's predicate form.
func MarshalPredicate(r *Record) ([]byte, error) {
	if r.V != 1 {
		return nil, fmt.Errorf("unsupported record version %d", r.V)
	}
	want, ok := bodyRegistry[r.Type]
	if !ok {
		return nil, fmt.Errorf("unknown record type %q", r.Type)
	}
	if r.Body == nil {
		return nil, fmt.Errorf("missing body for %q", r.Type)
	}
	wt := reflect.TypeOf(want()).Elem()
	bt := reflect.TypeOf(r.Body)
	if bt.Kind() != reflect.Pointer || bt.Elem() != wt {
		return nil, fmt.Errorf("body of %q is %T, want *%s", r.Type, r.Body, wt)
	}
	// Required list/map fields encode as []/{}, never null. Fields carrying
	// cs:"nullable" are left alone (03 §4 `?` = may be null). This mutates the
	// caller's body so the emitted form and the in-memory form agree.
	normalizeEmpty(reflect.ValueOf(r.Body).Elem())
	return marshalCanonical(r)
}

// normalizeEmpty sets nil slices and maps to their empty forms so required
// fields never encode as null.
func normalizeEmpty(v reflect.Value) {
	t := v.Type()
	if t.Kind() == reflect.Pointer {
		if v.IsNil() {
			return
		}
		normalizeEmpty(v.Elem())
		return
	}
	if t.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < t.NumField(); i++ {
		f := v.Field(i)
		sf := t.Field(i)
		if !f.CanSet() {
			continue
		}
		switch f.Kind() {
		case reflect.Slice:
			if f.IsNil() && !strings.Contains(sf.Tag.Get("cs"), "nullable") {
				f.Set(reflect.MakeSlice(f.Type(), 0, 0))
			}
		case reflect.Map:
			if f.IsNil() && !strings.Contains(sf.Tag.Get("cs"), "nullable") {
				f.Set(reflect.MakeMap(f.Type()))
			}
		case reflect.Pointer, reflect.Struct:
			normalizeEmpty(f)
		}
	}
}

// predicateJSON is the on-the-wire shape of Record.
type predicateJSON struct {
	V       int             `json:"v"`
	Type    string          `json:"type"`
	ID      string          `json:"id"`
	Session string          `json:"session"`
	Emitter string          `json:"emitter"`
	Eseq    uint64          `json:"eseq"`
	Eprev   string          `json:"eprev"`
	TS      string          `json:"ts"`
	Body    json.RawMessage `json:"body"`
}

// UnmarshalPredicate decodes predicate bytes: strict JSON, v == 1, a
// registered type, and a strictly decoded body.
func UnmarshalPredicate(data []byte) (*Record, error) {
	var p predicateJSON
	if err := unmarshalStrict(data, &p); err != nil {
		return nil, err
	}
	if p.V != 1 {
		return nil, fmt.Errorf("unsupported record version %d", p.V)
	}
	body, ok := NewBody(p.Type)
	if !ok {
		return nil, fmt.Errorf("unknown record type %q", p.Type)
	}
	if len(p.Body) == 0 {
		return nil, fmt.Errorf("missing body for %q", p.Type)
	}
	if err := unmarshalStrict(p.Body, body); err != nil {
		return nil, fmt.Errorf("body of %q: %w", p.Type, err)
	}
	if reflect.ValueOf(body).IsNil() {
		return nil, fmt.Errorf("body of %q is null", p.Type)
	}
	return &Record{
		V: p.V, Type: p.Type, ID: p.ID, Session: p.Session,
		Emitter: p.Emitter, Eseq: p.Eseq, Eprev: p.Eprev, TS: p.TS,
		Body: body,
	}, nil
}

// MarshalRecordLine encodes a complete stored line: record → statement →
// DSSE envelope with the supplied signature.
func MarshalRecordLine(r *Record, sig Signature) ([]byte, error) {
	pred, err := MarshalPredicate(r)
	if err != nil {
		return nil, err
	}
	stBytes, err := MarshalStatement(NewStatement(r.Session, pred))
	if err != nil {
		return nil, err
	}
	env := &Envelope{
		PayloadType: PayloadType,
		Payload:     stBytes,
		Signatures:  []Signature{sig},
	}
	return MarshalEnvelope(env)
}

// DecodeRecordLine decodes a stored line into its envelope, statement and
// record. The returned envelope's Payload bytes are the signed bytes; the
// statement's Predicate is the raw record JSON.
func DecodeRecordLine(line []byte) (*Envelope, *Statement, *Record, error) {
	env, err := UnmarshalEnvelope(line)
	if err != nil {
		return nil, nil, nil, err
	}
	st, err := UnmarshalStatement(env.Payload)
	if err != nil {
		return nil, nil, nil, err
	}
	r, err := UnmarshalPredicate(st.Predicate)
	if err != nil {
		return nil, nil, nil, err
	}
	return env, st, r, nil
}
