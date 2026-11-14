Upstream excerpt: DSSE protocol v1.0.2
Source: https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
Fetched 2026-11-14. Used for: PAE definition and test vector (spec 03 §1, §3).

PAE(type, body) = "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(body) + SP + body
  +  = concatenation
  SP = ASCII space [0x20]
  "DSSEv1" = ASCII [0x44, 0x53, 0x53, 0x45, 0x76, 0x31]
  LEN(s) = ASCII decimal encoding of the byte length of s, with no leading zeros

SIGNATURE = Sign(PAE(UTF8(PAYLOAD_TYPE), SERIALIZED_BODY))

Test vector (published in protocol.md):
  SERIALIZED_BODY = "hello world"
  PAYLOAD_TYPE    = "http://example.com/HelloWorld"
  PAE = "DSSEv1 29 http://example.com/HelloWorld 11 hello world"

Note: upstream allows standard OR URL-safe base64 in the envelope; spec 03 §1
pins standard base64 (canonical, RFC 4648 §3.5) — a deliberate narrowing, not a
contradiction.
