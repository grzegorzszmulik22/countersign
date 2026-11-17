# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""Strict JSON per spec 03 §1–§2.

Two layers, matching the reference behaviour bit for bit:

- ``check_json`` is a byte-level scanner enforcing UTF-8 input, no duplicate
  object keys, valid string escapes including surrogate pairing, RFC 8259
  numbers and bounded depth. Its error strings are the verifier's own
  ``json: byte N: ...`` diagnostics.
- ``go_typed`` decodes a parsed value into a declared type, rejecting
  unknown object fields and reporting type mismatches with the same
  ``json: cannot unmarshal ...`` / ``json: unknown field`` diagnostics a
  strict typed decoder produces.
"""


class SchemaError(Exception):
    """One E_SCHEMA-class decode failure; message is the verifier detail."""


# ---------------------------------------------------------------------------
# check_json: byte scanner.
# ---------------------------------------------------------------------------

_MAX_DEPTH = 64


def _rune_q(c):
    """Go %q of a single rune."""
    ch = chr(c)
    if ch == '"':
        return "'\"'"
    if ch == "'":
        return "'\\''"
    if ch == "\\":
        return "'\\\\'"
    if 0x20 <= c < 0x7F or c >= 0x80:
        return "'" + ch + "'"
    esc = {7: "a", 8: "b", 9: "t", 10: "n", 11: "v", 12: "f", 13: "r"}
    if c in esc:
        return "'\\" + esc[c] + "'"
    return "'\\x%02x'" % c


def _quote(s):
    """Go strconv.Quote for typical content."""
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif o < 0x20:
            out.append("\\x%02x" % o)
        elif o < 0x7F:
            out.append(ch)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _valid_utf8(data):
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


class _P:
    """The strict scanner: one complete JSON value or an error."""

    def __init__(self, d):
        self.d = d
        self.i = 0
        # When building the node tree we record, per value, (kind, val, raw).
        self.nodes = None

    def errf(self, fmt, *a):
        raise SchemaError("json: byte %d: %s" % (self.i, fmt % a))

    def ws(self):
        d, n = self.d, len(self.d)
        while self.i < n and d[self.i] in b" \t\n\r":
            self.i += 1

    def value(self, depth):
        if depth > _MAX_DEPTH:
            self.errf("nesting deeper than %d", _MAX_DEPTH)
        if self.i >= len(self.d):
            self.errf("unexpected end of input")
        c = self.d[self.i]
        if c == 0x7B:  # {
            return self._obj(depth)
        if c == 0x5B:  # [
            return self._arr(depth)
        if c == 0x22:  # "
            start = self.i
            self._str()
            raw = self.d[start:self.i]
            import json as _j
            return ("str", _j.loads(raw.decode("utf-8")), raw)
        if c == 0x74:  # t
            return self._lit(b"true", ("bool", True, b"true"))
        if c == 0x66:  # f
            return self._lit(b"false", ("bool", False, b"false"))
        if c == 0x6E:  # n
            return self._lit(b"null", ("null", None, b"null"))
        if c == 0x2D or (0x30 <= c <= 0x39):
            return self._num()
        self.errf("unexpected character %s", _rune_q(c))

    def _lit(self, s, node):
        if len(self.d) - self.i < len(s) or self.d[self.i:self.i + len(s)] != s:
            self.errf("invalid literal, expected %s", _quote(s.decode()))
        self.i += len(s)
        return node

    def _obj(self, depth):
        self.i += 1
        start = self.i - 1
        keys = {}
        self.ws()
        if self.i < len(self.d) and self.d[self.i] == 0x7D:
            self.i += 1
            return ("obj", [], self.d[start:self.i])
        pairs = []
        while True:
            self.ws()
            if self.i >= len(self.d) or self.d[self.i] != 0x22:
                self.errf("expected object key")
            kstart = self.i
            self._str()
            import json as _j
            try:
                key = _j.loads(self.d[kstart:self.i].decode("utf-8"))
            except Exception:
                self.errf("bad key: %s", self.d[kstart:self.i])
            if key in keys:
                self.errf("duplicate key %s", _quote(key))
            keys[key] = True
            self.ws()
            if self.i >= len(self.d) or self.d[self.i] != 0x3A:
                self.errf("expected ':'")
            self.i += 1
            self.ws()
            val = self.value(depth + 1)
            pairs.append((key, val))
            self.ws()
            if self.i >= len(self.d):
                self.errf("unterminated object")
            if self.d[self.i] == 0x7D:
                self.i += 1
                return ("obj", pairs, self.d[start:self.i])
            if self.d[self.i] != 0x2C:
                self.errf("expected ',' or '}'")
            self.i += 1

    def _arr(self, depth):
        self.i += 1
        start = self.i - 1
        self.ws()
        if self.i < len(self.d) and self.d[self.i] == 0x5D:
            self.i += 1
            return ("arr", [], self.d[start:self.i])
        items = []
        while True:
            self.ws()
            items.append(self.value(depth + 1))
            self.ws()
            if self.i >= len(self.d):
                self.errf("unterminated array")
            if self.d[self.i] == 0x5D:
                self.i += 1
                return ("arr", items, self.d[start:self.i])
            if self.d[self.i] != 0x2C:
                self.errf("expected ',' or ']'")
            self.i += 1

    def _str(self):
        self.i += 1
        while self.i < len(self.d):
            c = self.d[self.i]
            if c == 0x22:
                self.i += 1
                return
            if c == 0x5C:
                self.i += 1
                if self.i >= len(self.d):
                    self.errf("unterminated escape")
                e = self.d[self.i]
                self.i += 1
                if e in b'"\\/bfnrt':
                    continue
                if e == 0x75:  # u
                    self._u_escape()
                    continue
                self.errf("invalid escape '\\%c'", chr(e))
            elif c < 0x20:
                self.errf("unescaped control character")
            else:
                self.i += 1
        self.errf("unterminated string")

    def _hex4(self):
        if len(self.d) - self.i < 4:
            self.errf("short \\u escape")
        v = 0
        for c in self.d[self.i:self.i + 4]:
            v <<= 4
            if 0x30 <= c <= 0x39:
                v |= c - 0x30
            elif 0x61 <= c <= 0x66:
                v |= c - 0x61 + 10
            elif 0x41 <= c <= 0x46:
                v |= c - 0x41 + 10
            else:
                self.errf("bad hex digit %s", _rune_q(c))
        self.i += 4
        return v

    def _u_escape(self):
        r = self._hex4()
        if 0xD800 <= r <= 0xDBFF:
            if len(self.d) - self.i < 6 or self.d[self.i] != 0x5C \
                    or self.d[self.i + 1] != 0x75:
                self.errf("unpaired surrogate escape")
            self.i += 2
            lo = self._hex4()
            if lo < 0xDC00 or lo > 0xDFFF:
                self.errf("unpaired surrogate escape")
        elif 0xDC00 <= r <= 0xDFFF:
            self.errf("unpaired surrogate escape")

    def _num(self):
        start = self.i
        if self.d[self.i] == 0x2D:
            self.i += 1
        if self.i >= len(self.d):
            self.errf("bad number")
        if self.d[self.i] == 0x30:
            self.i += 1
        elif 0x31 <= self.d[self.i] <= 0x39:
            while self.i < len(self.d) and 0x30 <= self.d[self.i] <= 0x39:
                self.i += 1
        else:
            self.errf("bad number")
        if self.i < len(self.d) and self.d[self.i] == 0x2E:
            self.i += 1
            if self.i >= len(self.d) or not (0x30 <= self.d[self.i] <= 0x39):
                self.errf("bad number fraction")
            while self.i < len(self.d) and 0x30 <= self.d[self.i] <= 0x39:
                self.i += 1
        if self.i < len(self.d) and self.d[self.i] in (0x65, 0x45):
            self.i += 1
            if self.i < len(self.d) and self.d[self.i] in (0x2B, 0x2D):
                self.i += 1
            if self.i >= len(self.d) or not (0x30 <= self.d[self.i] <= 0x39):
                self.errf("bad number exponent")
            while self.i < len(self.d) and 0x30 <= self.d[self.i] <= 0x39:
                self.i += 1
        return ("num", self.d[start:self.i], self.d[start:self.i])


def parse_node(data):
    """check_json + node tree. Node = (kind, value, raw bytes) where kind is
    obj/arr/str/num/bool/null; obj value = [(key, node)] in order; str value =
    decoded string; num value = raw literal bytes."""
    if not _valid_utf8(data):
        raise SchemaError("input is not valid UTF-8")
    p = _P(data)
    p.ws()
    node = p.value(0)
    p.ws()
    if p.i != len(p.d):
        raise SchemaError("trailing data at byte %d" % p.i)
    return node


def check_json(data):
    """Strict scan only (raises SchemaError)."""
    parse_node(data)


# ---------------------------------------------------------------------------
# Typed decode: encoding/json semantics with DisallowUnknownFields.
# ---------------------------------------------------------------------------
# Specs:
#   "str" "int" "int64" "uint64" "float64" "bool" "raw" "b64"
#   ("opt", inner)                        — nullable
#   ("list", inner, go_type)              — e.g. "[]evidence.Signature"
#   ("map", inner, go_type)               — e.g. "map[string]string"
#   ("struct", go_name, go_type, fields)  — fields: ((json_name, spec), ...)

_GO_TYPE = {
    "str": "string", "int": "int", "int64": "int64", "uint64": "uint64",
    "float64": "float64", "bool": "bool", "raw": "json.RawMessage",
}


def _kind_desc(node):
    k = node[0]
    if k == "obj":
        return "object"
    if k == "arr":
        return "array"
    if k == "str":
        return "string"
    if k == "bool":
        return "bool"
    if k == "num":
        return "number"
    return "null"


def _type_err(node, go_type, ctx):
    """ctx = (struct_name, field_json_name) or None for top level."""
    desc = _kind_desc(node)
    if ctx is None:
        raise SchemaError(
            "json: cannot unmarshal %s into Go value of type %s"
            % (desc, go_type))
    raise SchemaError(
        "json: cannot unmarshal %s into Go struct field %s.%s of type %s"
        % (desc, ctx[0], ctx[1], go_type))


def _spec_type(spec):
    if isinstance(spec, str):
        return _GO_TYPE[spec]
    if spec[0] == "opt":
        return _spec_type(spec[1])
    if spec[0] == "list" or spec[0] == "map":
        return spec[2]
    return spec[2]  # struct


def _zero(spec):
    if isinstance(spec, str):
        return {"str": "", "int": 0, "int64": 0, "uint64": 0, "float64": 0.0,
                "bool": False, "b64": b""}[spec] if spec != "raw" else None
    t = spec[0]
    if t == "opt" or t == "raw":
        return None
    if t == "list" or t == "map":
        return None
    return {k: _zero(s) for k, s in spec[3]}


_INT_RE_LO = -(1 << 63)
_INT_RE_HI = (1 << 63) - 1
_UINT_HI = (1 << 64) - 1


def _int_lit(raw):
    """JSON number literal → int, or None if not a pure integer."""
    s = raw.decode("ascii")
    if s[0] == "-":
        digits = s[1:]
    else:
        digits = s
    if not digits.isdigit():
        return None
    return int(s)


def _b64_decode(s):
    """Go base64.StdEncoding.DecodeString → bytes or raise with Go message.
    Go skips \\r and \\n inside the input; positions reported are input
    offsets."""
    import base64 as _b
    data = s.encode("utf-8")
    alpha = (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
             b"0123456789+/")
    # Positions of content bytes (excluding skipped \r\n).
    pos = [i for i, c in enumerate(data) if c not in (0x0D, 0x0A)]
    clean = bytes(data[i] for i in pos)
    n = len(clean)
    i = 0
    while i < n:
        q = clean[i:i + 4]
        if len(q) < 4:
            raise SchemaError(
                "invalid base64: illegal base64 data at input byte %d"
                % (pos[i] if i < n else (pos[-1] + 1 if pos else 0)))
        pad = 0
        for j, c in enumerate(q):
            if c == 0x3D:  # =
                if j < 2:
                    raise SchemaError(
                        "invalid base64: illegal base64 data at input "
                        "byte %d" % pos[i + j])
                pad += 1
            elif c in alpha:
                if pad:
                    raise SchemaError(
                        "invalid base64: illegal base64 data at input "
                        "byte %d" % pos[i + j])
            else:
                raise SchemaError(
                    "invalid base64: illegal base64 data at input byte %d"
                    % pos[i + j])
        if pad and i + 4 != n:
            raise SchemaError(
                "invalid base64: illegal base64 data at input byte %d"
                % pos[i + 4])
        i += 4
    return _b.b64decode(clean)


def go_typed(node, spec):
    """Decode node per spec → Python value. ctx tracking matches Go's
    UnmarshalTypeError: the outermost struct name (errorContext) plus
    the dotted JSON field path from the root."""
    return _typed(node, spec, "", None)


def _typed(node, spec, path, inner):
    kind = node[0]
    ctx = (inner, path) if inner is not None else None
    if kind == "null":
        if spec == "raw":
            return node[2]  # RawMessage keeps the literal bytes
        if isinstance(spec, tuple) and spec[0] == "opt":
            return None
        return _zero(spec)

    if isinstance(spec, str):
        t = spec
        if t == "str":
            if kind != "str":
                _type_err(node, "string", ctx)
            return node[1]
        if t == "bool":
            if kind != "bool":
                _type_err(node, "bool", ctx)
            return node[1]
        if t in ("int", "int64", "uint64", "float64"):
            if kind != "num":
                _type_err(node, _GO_TYPE[t], ctx)
            raw = node[1]

            def num_err(go_type):
                # Numeric-parse failures embed the literal in the Value.
                n = ("num", "number " + raw.decode("ascii"), None)
                if ctx is None:
                    raise SchemaError(
                        "json: cannot unmarshal %s into Go value of type %s"
                        % (n[1], go_type))
                raise SchemaError(
                    "json: cannot unmarshal %s into Go struct field %s.%s "
                    "of type %s" % (n[1], ctx[0], ctx[1], go_type))
            if t == "float64":
                s = raw.decode("ascii")
                try:
                    v = float(s)
                except ValueError:
                    num_err("float64")
                mant = s.split("e")[0].split("E")[0]
                if v in (float("inf"), float("-inf")) or (
                        v == 0.0 and any(c.isdigit() and c != "0"
                                         for c in mant)):
                    num_err("float64")
                return v
            v = _int_lit(raw)
            if v is None or (t == "uint64" and raw[:1] == b"-"):
                num_err(_GO_TYPE[t])
            if t == "uint64":
                if v > _UINT_HI:
                    num_err("uint64")
            else:
                if v < _INT_RE_LO or v > _INT_RE_HI:
                    num_err(_GO_TYPE[t])
            return v
        if t == "raw":
            return node[2]
        if t == "b64":
            # Custom unmarshaler: inner json.Unmarshal(data, &string).
            if kind != "str":
                desc = _kind_desc(node)
                raise SchemaError(
                    "json: cannot unmarshal %s into Go value of type string"
                    % desc)
            raw = _b64_decode(node[1])
            import base64 as _b
            if _b.b64encode(raw).decode() != node[1]:
                raise SchemaError("non-canonical base64")
            return raw
        raise AssertionError(t)

    t = spec[0]
    if t == "opt":
        return _typed(node, spec[1], path, inner)
    if t == "list":
        if kind != "arr":
            _type_err(node, spec[2], ctx)
        return [_typed(x, spec[1], path, inner) for x in node[1]]
    if t == "map":
        if kind != "obj":
            _type_err(node, spec[2], ctx)
        return {k: _typed(v, spec[1], path, inner) for k, v in node[1]}
    if t == "struct":
        if kind != "obj":
            _type_err(node, spec[2], ctx)
        name = spec[1]
        fields = dict(spec[3])
        out = {}
        for k, v in node[1]:
            f = fields.get(k)
            if f is None:
                raise SchemaError('json: unknown field "%s"' % k)
            out[k] = _typed(v, f, path + "." + k if path else k,
                            inner if inner is not None else name)
        # Absent keys keep their zero values.
        for k, s in spec[3]:
            if k not in out:
                out[k] = _zero(s)
        return out
    raise AssertionError(t)


def unmarshal_strict(data, spec):
    """check_json then typed decode → value. Raises SchemaError."""
    node = parse_node(data)
    return go_typed(node, spec)


# ---------------------------------------------------------------------------
# encoding/json-compatible scanner for non-record inputs (manifest, index,
# trusted keys). Same acceptance rules minus the duplicate-key ban, with
# encoding/json-style diagnostics.
# ---------------------------------------------------------------------------


def _gchar(c):
    ch = chr(c)
    if 0x20 <= c < 0x7F:
        return "'%s'" % ch
    esc = {9: "\\t", 10: "\\n", 13: "\\r"}
    if c in esc:
        return "'" + esc[c] + "'"
    return "'\\u%04x'" % c


def _gws(d, i):
    while i < len(d) and d[i] in b" \t\n\r":
        i += 1
    return i


def _gerr(fmt, *a):
    raise SchemaError(fmt % a)


def _gstr(d, i):
    """String at i → (decoded str, end)."""
    i += 1
    out = []
    while i < len(d):
        c = d[i]
        if c == 0x22:
            return "".join(out), i + 1
        if c == 0x5C:
            i += 1
            if i >= len(d):
                _gerr("unexpected end of JSON input")
            e = d[i]
            i += 1
            if e in b'"\\/':
                out.append(chr(e))
            elif e == 0x62:
                out.append("\b")
            elif e == 0x66:
                out.append("\f")
            elif e == 0x6E:
                out.append("\n")
            elif e == 0x72:
                out.append("\r")
            elif e == 0x74:
                out.append("\t")
            elif e == 0x75:
                if i + 4 > len(d):
                    _gerr("unexpected end of JSON input")
                hv = 0
                for c2 in d[i:i + 4]:
                    hv <<= 4
                    if 0x30 <= c2 <= 0x39:
                        hv |= c2 - 0x30
                    elif 0x61 <= c2 <= 0x66:
                        hv |= c2 - 0x61 + 10
                    elif 0x41 <= c2 <= 0x46:
                        hv |= c2 - 0x41 + 10
                    else:
                        _gerr("invalid character %s in \\u hexadecimal "
                              "character escape" % _gchar(c2))
                i += 4
                out.append(chr(hv))
            else:
                _gerr("invalid character %s in string escape code"
                      % _gchar(e))
        elif c < 0x20:
            _gerr("invalid character %s in string literal" % _gchar(c))
        else:
            # Multi-byte UTF-8: copy raw.
            n = 1
            if c >= 0xF0:
                n = 4
            elif c >= 0xE0:
                n = 3
            elif c >= 0xC0:
                n = 2
            out.append(d[i:i + n].decode("utf-8", "replace"))
            i += n
    _gerr("unexpected end of JSON input")


def _gvalue(d, i, top):
    """One JSON value at i → (node, end). encoding/json diagnostics."""
    i = _gws(d, i)
    if i >= len(d):
        if top:
            _gerr("unexpected end of JSON input")
        _gerr("unexpected end of JSON input")
    c = d[i]
    if c == 0x7B:
        i += 1
        pairs = []
        i = _gws(d, i)
        if i < len(d) and d[i] == 0x7D:
            return ("obj", pairs, d[i - 1:i + 1]), i + 1
        while True:
            i = _gws(d, i)
            if i >= len(d):
                _gerr("unexpected end of JSON input")
            if d[i] != 0x22:
                _gerr("invalid character %s looking for beginning of "
                      "object key string" % _gchar(d[i]))
            k, i = _gstr(d, i)
            i = _gws(d, i)
            if i >= len(d):
                _gerr("unexpected end of JSON input")
            if d[i] != 0x3A:
                _gerr("invalid character %s after object key" % _gchar(d[i]))
            v, i = _gvalue(d, i + 1, False)
            pairs.append((k, v))
            i = _gws(d, i)
            if i >= len(d):
                _gerr("unexpected end of JSON input")
            if d[i] == 0x7D:
                return ("obj", pairs, None), i + 1
            if d[i] != 0x2C:
                _gerr("invalid character %s after object key:value pair"
                      % _gchar(d[i]))
            i += 1
    if c == 0x5B:
        i += 1
        items = []
        i = _gws(d, i)
        if i < len(d) and d[i] == 0x5D:
            return ("arr", items, None), i + 1
        while True:
            v, i = _gvalue(d, i, False)
            items.append(v)
            i = _gws(d, i)
            if i >= len(d):
                _gerr("unexpected end of JSON input")
            if d[i] == 0x5D:
                return ("arr", items, None), i + 1
            if d[i] != 0x2C:
                _gerr("invalid character %s after array element"
                      % _gchar(d[i]))
            i += 1
    if c == 0x22:
        s, i = _gstr(d, i)
        return ("str", s, None), i
    if c == 0x74:
        for j, e in enumerate(b"rue"):
            if i + 1 + j >= len(d):
                _gerr("unexpected end of JSON input")
            if d[i + 1 + j] != e:
                _gerr("invalid character %s in literal true (expecting %s)"
                      % (_gchar(d[i + 1 + j]), _gchar(e)))
        return ("bool", True, None), i + 4
    if c == 0x66:
        for j, e in enumerate(b"alse"):
            if i + 1 + j >= len(d):
                _gerr("unexpected end of JSON input")
            if d[i + 1 + j] != e:
                _gerr("invalid character %s in literal false (expecting %s)"
                      % (_gchar(d[i + 1 + j]), _gchar(e)))
        return ("bool", False, None), i + 5
    if c == 0x6E:
        for j, e in enumerate(b"ull"):
            if i + 1 + j >= len(d):
                _gerr("unexpected end of JSON input")
            if d[i + 1 + j] != e:
                _gerr("invalid character %s in literal null (expecting %s)"
                      % (_gchar(d[i + 1 + j]), _gchar(e)))
        return ("null", None, None), i + 4
    if c == 0x2D or 0x30 <= c <= 0x39:
        j = i
        if d[j] == 0x2D:
            j += 1
            if j >= len(d):
                _gerr("unexpected end of JSON input")
            if not (0x30 <= d[j] <= 0x39):
                _gerr("invalid character %s in numeric literal"
                      % _gchar(d[j]))
        if d[j] == 0x30:
            j += 1
        else:
            while j < len(d) and 0x30 <= d[j] <= 0x39:
                j += 1
        if j < len(d) and d[j] == 0x2E:
            j += 1
            if j >= len(d):
                _gerr("unexpected end of JSON input")
            if not (0x30 <= d[j] <= 0x39):
                _gerr("invalid character %s after decimal point in "
                      "numeric literal" % _gchar(d[j]))
            while j < len(d) and 0x30 <= d[j] <= 0x39:
                j += 1
        if j < len(d) and d[j] in (0x65, 0x45):
            j += 1
            if j < len(d) and d[j] in (0x2B, 0x2D):
                j += 1
            if j >= len(d):
                _gerr("unexpected end of JSON input")
            if not (0x30 <= d[j] <= 0x39):
                _gerr("invalid character %s in exponent of numeric literal"
                      % _gchar(d[j]))
            while j < len(d) and 0x30 <= d[j] <= 0x39:
                j += 1
        return ("num", d[i:j], None), j
    _gerr("invalid character %s looking for beginning of value" % _gchar(c))


def go_parse_first(data):
    """Parse one JSON value with encoding/json semantics → (node, endpos).
    node kind/values as in parse_node but without dup-key or UTF-8 checks."""
    if not data.strip(b" \t\n\r"):
        raise SchemaError("EOF")
    node, i = _gvalue(data, 0, True)
    return node, i

