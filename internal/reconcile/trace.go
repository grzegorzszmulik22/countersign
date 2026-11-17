// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// Abstract trace files (docs/refreconcile.md): one JSON object per line,
// a trace.meta first line then record bodies in log order.
package reconcile

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// TraceFormatError marks a malformed trace file.
type TraceFormatError struct{ msg string }

func (e *TraceFormatError) Error() string { return e.msg }

// ParseTrace reads trace lines -> (meta, records).
func ParseTrace(r io.Reader) (map[string]any, []rec, error) {
	var meta map[string]any
	var records []rec
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		v, err := DecodeJSON([]byte(line))
		if err != nil {
			return nil, nil, &TraceFormatError{fmt.Sprintf("line %d: invalid JSON: %s", n, err)}
		}
		obj, ok := v.(map[string]any)
		if !ok {
			return nil, nil, &TraceFormatError{fmt.Sprintf("line %d: not a JSON object with a type", n)}
		}
		if _, ok := obj["type"].(string); !ok {
			return nil, nil, &TraceFormatError{fmt.Sprintf("line %d: not a JSON object with a type", n)}
		}
		if meta == nil {
			if obj["type"] != "trace.meta" {
				return nil, nil, &TraceFormatError{fmt.Sprintf(
					"line %d: first record must be trace.meta, not %v", n, obj["type"])}
			}
			meta = obj
			continue
		}
		records = append(records, obj)
	}
	if err := sc.Err(); err != nil {
		return nil, nil, err
	}
	if meta == nil {
		return nil, nil, &TraceFormatError{"empty trace"}
	}
	return meta, records, nil
}

// ParseTraceLine parses one batch line {"meta":…,"records":[…]}.
func ParseTraceLine(line string) (map[string]any, []rec, error) {
	v, err := DecodeJSON([]byte(line))
	if err != nil {
		return nil, nil, err
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("not a JSON object")
	}
	meta := mdict(obj, "meta")
	if meta == nil {
		return nil, nil, fmt.Errorf("no meta object")
	}
	var records []rec
	for _, rv := range asList(mget(obj, "records")) {
		m, ok := rv.(map[string]any)
		if !ok {
			return nil, nil, fmt.Errorf("record is not an object")
		}
		records = append(records, m)
	}
	return meta, records, nil
}

// MarshalResult renders the result JSON (sorted keys via encoding/json).
func MarshalResult(res *Result) ([]byte, error) {
	return json.Marshal(res)
}
