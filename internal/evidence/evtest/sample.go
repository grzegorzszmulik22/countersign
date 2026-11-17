// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// Package evtest produces schema-valid sample record bodies for tests and
// test-vector generation. Values come from the cs tags on the evidence body
// structs; it is test support code, not part of the record format.
package evtest

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/countersign/countersign/internal/evidence"
)

const (
	sampleULID    = "01K7D7JQ9Y8T4X2Z6B4H4F4F4F"
	sampleHex64   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	sampleHex32   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	sampleTS      = "2026-11-14T00:00:00.000000000Z"
	sampleEmitter = "broker/" + sampleULID
	sampleIP      = "10.0.0.1"
)

var rawMessageType = reflect.TypeOf(json.RawMessage{})

// Sample returns a populated body instance for the record type, with every
// field set to a schema-valid value.
func Sample(typeName string) (any, error) {
	body, ok := evidence.NewBody(typeName)
	if !ok {
		return nil, fmt.Errorf("unknown record type %q", typeName)
	}
	populate(reflect.ValueOf(body).Elem(), "")
	return body, nil
}

func populate(v reflect.Value, tag string) {
	t := v.Type()
	if t == rawMessageType {
		v.Set(reflect.ValueOf(json.RawMessage(`{"sample":1}`)))
		return
	}
	switch v.Kind() {
	case reflect.Pointer:
		v.Set(reflect.New(t.Elem()))
		populate(v.Elem(), tag)
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			populate(v.Field(i), t.Field(i).Tag.Get("cs"))
		}
	case reflect.Slice:
		elem := reflect.New(t.Elem()).Elem()
		populate(elem, tag)
		v.Set(reflect.Append(v, elem))
	case reflect.Map:
		k := reflect.New(t.Key()).Elem()
		e := reflect.New(t.Elem()).Elem()
		populate(k, "")
		populate(e, "")
		v.Set(reflect.MakeMap(t))
		v.SetMapIndex(k, e)
	case reflect.String:
		v.SetString(sampleString(tag))
	case reflect.Int64, reflect.Int:
		if tag == "port" {
			v.SetInt(3128)
		} else {
			v.SetInt(1)
		}
	case reflect.Uint64, reflect.Uint:
		v.SetUint(1)
	case reflect.Float64:
		v.SetFloat(1.5)
	case reflect.Bool:
		v.SetBool(true)
	}
}

func sampleString(tag string) string {
	for _, opt := range strings.Split(tag, ",") {
		switch {
		case opt == "ulid":
			return sampleULID
		case opt == "hex64":
			return sampleHex64
		case opt == "hex32":
			return sampleHex32
		case opt == "ts":
			return sampleTS
		case opt == "emitter":
			return sampleEmitter
		case opt == "ip":
			return sampleIP
		case strings.HasPrefix(opt, "enum:"):
			return strings.Split(strings.TrimPrefix(opt, "enum:"), "|")[0]
		}
	}
	return "x"
}
