// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package inspect

// sseSplitter incrementally splits a server-sent-event byte stream into
// events. One event = zero or more "field: value" lines ended by a blank
// line (WHATWG SSE). Data fields accumulate across lines joined with
// '\n'; lines starting with ':' are comments and ignored. Lines ending
// with CR LF are accepted; a trailing CR is stripped from the line.
//
// The splitter is byte-exact about event boundaries: evStart of a
// dispatched event is the absolute offset of the first byte of its first
// line, so the broker can hold exactly "the bytes completing" a block.
type sseSplitter struct {
	abs     int64  // bytes consumed so far
	lineOff int64  // abs offset where the pending line began
	evOff   int64  // abs offset where the pending event began (-1: none)
	line    []byte // pending line bytes (not yet \n-terminated)
	evt     string // pending event: last "event:" field seen
	data    []byte // pending event: accumulated "data:" payloads
	hasData bool
	inEvent bool // a field/comment line for the current event was seen
}

// sseEvent is one dispatched event. start is its absolute byte offset in
// the stream; end is the offset just past its terminating blank line.
type sseEvent struct {
	start, end int64
	event      string
	data       []byte
}

// feed consumes b and returns every event completed within it.
func (s *sseSplitter) feed(b []byte) ([]sseEvent, error) {
	var out []sseEvent
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c == '\n' {
			ev, err := s.endLine()
			if err != nil {
				return out, err
			}
			if ev != nil {
				out = append(out, *ev)
			}
			s.abs += int64(len(s.line)) // line bytes already counted below
			s.line = s.line[:0]
			s.abs++
			s.lineOff = s.abs
			continue
		}
		s.line = append(s.line, c)
	}
	return out, nil
}

// endLine processes one completed line (contents in s.line, terminator
// consumed). A blank line dispatches the pending event.
func (s *sseSplitter) endLine() (*sseEvent, error) {
	line := s.line
	if len(line) > 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}
	if len(line) == 0 {
		// Blank line: dispatch. An event with no fields at all is a
		// stray blank line and dispatches nothing.
		if !s.inEvent {
			return nil, nil
		}
		ev := &sseEvent{
			start: s.evOff,
			end:   s.abs + int64(len(s.line)) + 1, // includes the blank line's \n
			event: s.evt,
			data:  s.data,
		}
		s.evt = ""
		s.data = nil
		s.hasData = false
		s.inEvent = false
		return ev, nil
	}
	if !s.inEvent {
		s.inEvent = true
		s.evOff = s.lineOff
	}
	if line[0] == ':' {
		return nil, nil // comment
	}
	// field: value — a single leading space after the colon is stripped.
	name, val, _ := cutField(line)
	switch name {
	case "event":
		s.evt = val
	case "data":
		if s.hasData {
			s.data = append(s.data, '\n')
		}
		s.data = append(s.data, val...)
		s.hasData = true
	case "id", "retry":
		// known but unused fields
	default:
		// unknown fields ignored per WHATWG SSE
	}
	return nil, nil
}

func cutField(line []byte) (name, val string, hadColon bool) {
	for i, c := range line {
		if c == ':' {
			name = string(line[:i])
			val = string(line[i+1:])
			if len(val) > 0 && val[0] == ' ' {
				val = val[1:]
			}
			return name, val, true
		}
	}
	// field with no colon: whole line is the name, value empty.
	return string(line), "", false
}

// pending reports whether bytes were consumed that never formed a
// dispatched event (a partial line, or event lines without the
// blank-line terminator). Used at stream end to detect a cut.
func (s *sseSplitter) pending() bool {
	return len(s.line) > 0 || s.inEvent
}
