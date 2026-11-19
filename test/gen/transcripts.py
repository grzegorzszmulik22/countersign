#!/usr/bin/env python3
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Regenerate test/vectors/transcripts/** (M8). Each vector is a wire
# response body (<name>.sse or <name>.json) plus <name>.expected.json
# carrying the intents an inspector must extract, computed with the
# Python reference canonicalizer (ref/python/refreconcile) — never the
# Go code under test. Tracking vectors are request/response scripts with
# the expected record sequence alongside.
#
# Wire shapes follow the pinned upstream documentation excerpts kept
# under evidence/<chunk>/<ts>/upstream/ (Anthropic Messages streaming,
# OpenAI Responses streaming, OpenAI Chat Completions streaming).

import hashlib
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "ref", "python"))
from refreconcile.canon import canon_sha256  # noqa: E402

ROOT = os.path.join(REPO, "test", "vectors", "transcripts")

J = lambda o: json.dumps(o, separators=(",", ":"), ensure_ascii=False)

# Marker strings are planted in text/result content; the ledger scan
# (C8.3.5) proves they never escape into records.
MARK = "MK" + hashlib.sha256(b"countersign-marker").hexdigest()[:12]

# ------------------------------------------------------------------
# expected intent computation


def _input_digest(raw):
    """(sha256, len) for an input transmitted as raw bytes/text.

    raw is str: the transmitted input bytes (assembled partial_json or a
    member's wire serialization). A JSON document digests canonically;
    a bare string digests as the string value (freeform inputs).
    """
    b = raw.encode("utf-8")
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError:
        doc = raw
    return canon_sha256(doc), len(b)


def exp_intent(iid, tool, executor, raw):
    sha, ln = _input_digest(raw)
    return {
        "intent_id": iid,
        "tool": tool,
        "executor": executor,
        "input_sha256": sha,
        "input_len": ln,
    }


def write_vector(d, name, wire, provider, fmt, model, intents,
                 unparsed=False, detail_sub="", markers=()):
    with open(os.path.join(ROOT, d, name + "." + fmt), "wb") as f:
        f.write(wire.encode("utf-8"))
    exp = {
        "provider": provider,
        "format": "sse" if fmt == "sse" else "json",
        "model": model,
        "intents": intents,
        "unparsed": unparsed,
        "detail_substring": detail_sub,
        "markers": list(markers),
    }
    with open(os.path.join(ROOT, d, name + ".expected.json"), "w") as f:
        json.dump(exp, f, indent=2)
        f.write("\n")


# ------------------------------------------------------------------
# Anthropic Messages wire builders (pinned docs: message_start,
# content_block_start/delta/stop, message_delta, message_stop)

MODEL_A = "claude-opus-4-1-20250805"


def aev(name, data):
    return "event: " + name + "\ndata: " + J(data) + "\n\n"


def a_msg_start(model=MODEL_A):
    return aev("message_start", {
        "type": "message_start",
        "message": {
            "id": "msg_01XyZ", "type": "message", "role": "assistant",
            "model": model, "content": [], "stop_reason": None,
            "stop_sequence": None,
            "usage": {"input_tokens": 25, "output_tokens": 1},
        },
    })


def a_block_start(idx, block):
    return aev("content_block_start", {
        "type": "content_block_start", "index": idx,
        "content_block": block,
    })


def a_delta(idx, delta):
    return aev("content_block_delta", {
        "type": "content_block_delta", "index": idx, "delta": delta,
    })


def a_block_stop(idx):
    return aev("content_block_stop", {
        "type": "content_block_stop", "index": idx,
    })


def a_msg_end(stop="tool_use"):
    return (aev("message_delta", {
        "type": "message_delta",
        "delta": {"stop_reason": stop, "stop_sequence": None},
        "usage": {"output_tokens": 15},
    }) + aev("message_stop", {"type": "message_stop"}))


def a_ping():
    return aev("ping", {"type": "ping"})


def a_tool_stream(iid, tool, input_obj, idx=0, frags=3, kind="tool_use"):
    """SSE for one tool_use/server_tool_use block; input_json_delta
    fragments carry input_obj's compact JSON."""
    s = J(input_obj)
    parts = []
    n = max(1, frags)
    step = max(1, (len(s) + n - 1) // n)
    for i in range(0, len(s), step):
        parts.append(s[i:i + step])
    if not parts:
        parts = [""]
    blk = {"type": kind, "id": iid, "name": tool, "input": {}}
    out = a_block_start(idx, blk)
    for p in parts:
        out += a_delta(idx, {"type": "input_json_delta", "partial_json": p})
    out += a_block_stop(idx)
    return out


def a_text_stream(text, idx):
    return (a_block_start(idx, {"type": "text", "text": ""})
            + a_delta(idx, {"type": "text_delta", "text": text})
            + a_block_stop(idx))


def a_json_body(blocks, model=MODEL_A, stop="tool_use"):
    return J({
        "id": "msg_01XyZ", "type": "message", "role": "assistant",
        "model": model, "content": blocks, "stop_reason": stop,
        "stop_sequence": None,
        "usage": {"input_tokens": 25, "output_tokens": 40},
    })


def gen_anthropic():
    d = "anthropic"
    i1 = {"command": "ls -la /tmp"}
    i1s = J(i1)

    # 1. single tool call, SSE + JSON
    write_vector(d, "single-call-sse",
                 a_msg_start() + a_tool_stream("toolu_01A7VoCkEoFxTwmRs6eT8V7X", "Bash", i1) + a_msg_end(),
                 "anthropic", "sse", MODEL_A,
                 [exp_intent("toolu_01A7VoCkEoFxTwmRs6eT8V7X", "Bash", "sandbox", i1s)])
    write_vector(d, "single-call-json",
                 a_json_body([{"type": "tool_use", "id": "toolu_01A7VoCkEoFxTwmRs6eT8V7X",
                               "name": "Bash", "input": i1}]),
                 "anthropic", "json", MODEL_A,
                 [exp_intent("toolu_01A7VoCkEoFxTwmRs6eT8V7X", "Bash", "sandbox", i1s)])

    # 2. several tool calls in one turn
    c2 = [("toolu_02M3y7f2T0hKkLvPqZy4Jb", "Bash", {"command": "git status"}),
          ("toolu_02M3y7f2T0hKkLvPqZy4Jc", "Read", {"file_path": "/etc/hosts"}),
          ("toolu_02M3y7f2T0hKkLvPqZy4Jd", "WebSearch", {"query": "jcs rfc 8785"})]
    s = a_msg_start()
    exps = []
    for k, (iid, tool, inp) in enumerate(c2):
        s += a_tool_stream(iid, tool, inp, idx=k)
        exps.append(exp_intent(iid, tool, "sandbox", J(inp)))
    s += a_msg_end()
    write_vector(d, "multi-call-sse", s, "anthropic", "sse", MODEL_A, exps)

    # 3. interleaved text and tool calls
    t1, t2 = "Reading the file for you " + MARK + "-a", "Done " + MARK + "-b"
    cA = ("toolu_03Int0rL3av3dC4ll0000a", "Read", {"file_path": "/tmp/a.txt"})
    cB = ("toolu_03Int0rL3av3dC4ll0000b", "Bash", {"command": "cat /tmp/a.txt"})
    s = (a_msg_start() + a_text_stream(t1, 0)
         + a_tool_stream(cA[0], cA[1], cA[2], idx=1)
         + a_text_stream(t2, 2)
         + a_tool_stream(cB[0], cB[1], cB[2], idx=3)
         + a_msg_end())
    write_vector(d, "interleaved-sse", s, "anthropic", "sse", MODEL_A,
                 [exp_intent(cA[0], cA[1], "sandbox", J(cA[2])),
                  exp_intent(cB[0], cB[1], "sandbox", J(cB[2]))],
                 markers=[t1, t2])

    # 4. tool input streamed in many small fragments
    i4 = {"command": "printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' > /tmp/f.txt",
          "env": {"A": "1"}}
    s = a_msg_start() + a_tool_stream("toolu_04Fr4gm3nt3dInpUt00000", "Bash", i4,
                                      idx=0, frags=41) + a_msg_end()
    write_vector(d, "fragments-sse", s, "anthropic", "sse", MODEL_A,
                 [exp_intent("toolu_04Fr4gm3nt3dInpUt00000", "Bash", "sandbox", J(i4))])

    # 5. empty input
    s = (a_msg_start()
         + a_block_start(0, {"type": "tool_use", "id": "toolu_05EmptyInpUt0000000",
                             "name": "GetTime", "input": {}})
         + a_block_stop(0)
         + a_msg_end())
    write_vector(d, "empty-input-sse", s, "anthropic", "sse", MODEL_A,
                 [exp_intent("toolu_05EmptyInpUt0000000", "GetTime", "sandbox", "{}")])
    write_vector(d, "empty-input-json",
                 a_json_body([{"type": "tool_use", "id": "toolu_05EmptyInpUt0000000",
                               "name": "GetTime", "input": {}}]),
                 "anthropic", "json", MODEL_A,
                 [exp_intent("toolu_05EmptyInpUt0000000", "GetTime", "sandbox", "{}")])

    # 6. very large input (1 MiB): one tool_use whose command value is a
    #    MiB of deterministic text.
    big = ("echo '" + "0123456789abcdef" * 4096 + "0123456789abcdef" * 4096 +
           "0123456789abcdef" * 4096 + "0123456789abcdef" * 4096 +
           "0123456789abcdef" * 4096 + "0123456789abcdef" * 4096 +
           "0123456789abcdef" * 4096 + "0123456789abcdef" * 4096 +
           "' > /tmp/big")
    big = big[:1 << 20]
    i6 = {"command": big}
    s = a_msg_start() + a_tool_stream("toolu_06L4rg3InpUtOnE6iB0000", "Bash", i6,
                                      idx=0, frags=64) + a_msg_end()
    write_vector(d, "large-input-sse", s, "anthropic", "sse", MODEL_A,
                 [exp_intent("toolu_06L4rg3InpUtOnE6iB0000", "Bash", "sandbox", J(i6))])

    # 7. provider-executed tool: server_tool_use + its result block.
    i7 = {"query": "latest jcs json canonicalization"}
    s = (a_msg_start()
         + a_tool_stream("srvtoolu_07W3bS34rchC4ll000", "web_search", i7,
                         idx=0, kind="server_tool_use")
         + a_block_start(1, {"type": "web_search_tool_result",
                             "tool_use_id": "srvtoolu_07W3bS34rchC4ll000",
                             "content": [{"type": "web_search_result",
                                          "url": "https://example.test/r",
                                          "title": "result"}]})
         + a_block_stop(1)
         + a_msg_end())
    write_vector(d, "server-tool-sse", s, "anthropic", "sse", MODEL_A,
                 [exp_intent("srvtoolu_07W3bS34rchC4ll000", "web_search", "provider", J(i7))])

    # 8. unknown event names, unknown block types, unknown delta types:
    #    all ignored; the one real tool_use still declares.
    i8 = {"n": 1}
    s = (a_msg_start()
         + aev("flux_event", {"type": "flux_event", "z": 1})
         + a_block_start(0, {"type": "quantum_block", "spooky": True})
         + a_delta(0, {"type": "entangle_delta", "bits": "0101"})
         + a_block_stop(0)
         + aev("another_unknown", {"type": "another_unknown"})
         + a_tool_stream("toolu_08Unkn0wnTyp3sIgN0r3d", "Bash", i8, idx=1)
         + a_msg_end())
    write_vector(d, "unknown-sse", s, "anthropic", "sse", MODEL_A,
                 [exp_intent("toolu_08Unkn0wnTyp3sIgN0r3d", "Bash", "sandbox", J(i8))])

    # 9. provider error event mid-stream: the completed call stands;
    #    everything after is a stream fault.
    i9 = {"x": True}
    s = (a_msg_start()
         + a_tool_stream("toolu_09Err0rM1dStr34m0000", "Bash", i9, idx=0)
         + aev("error", {"type": "error",
                         "error": {"type": "overloaded_error",
                                   "message": "Overloaded"}}))
    write_vector(d, "error-mid-sse", s, "anthropic", "sse", MODEL_A,
                 [exp_intent("toolu_09Err0rM1dStr34m0000", "Bash", "sandbox", J(i9))],
                 unparsed=True, detail_sub="error")

    # 10. stream cut mid-block: deltas arrive, no stop, EOF.
    i10s = J({"command": "rm -rf /tmp/scratch"})
    half = i10s[:len(i10s) // 2]
    s = (a_msg_start()
         + a_block_start(0, {"type": "tool_use", "id": "toolu_10CutM1dBl0ck00000",
                             "name": "Bash", "input": {}})
         + a_delta(0, {"type": "input_json_delta", "partial_json": half}))
    write_vector(d, "cut-midblock-sse", s, "anthropic", "sse", MODEL_A,
                 [], unparsed=True, detail_sub="cut")

    # 11. text-only turns (no intents), both shapes.
    s = a_msg_start() + a_text_stream("No tools needed " + MARK + "-t", 0) \
        + a_msg_end(stop="end_turn")
    write_vector(d, "text-only-sse", s, "anthropic", "sse", MODEL_A, [],
                 markers=["No tools needed " + MARK + "-t"])
    write_vector(d, "text-only-json",
                 a_json_body([{"type": "text", "text": "plain " + MARK + "-tj"}],
                             stop="end_turn"),
                 "anthropic", "json", MODEL_A, [],
                 markers=["plain " + MARK + "-tj"])

    # 12. credential-shaped material inside inputs (M8.5): previews show
    #     [REDACTED:<shape>]; digests stay over the original bytes.
    # Padding places the AWS key so it straddles the 256-byte preview
    # cap: redaction must run before truncation or a key fragment leaks.
    i12 = {"command": "aws s3 ls " + "x" * 215 + " AKIAIOSFODNN7EXAMPLE",
           "url": "https://u:ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcd1234@h/x"}
    s = a_msg_start() + a_tool_stream("toolu_12Cr3d3nt14lSh4p3s00", "Bash", i12,
                                      idx=0, frags=5) + a_msg_end()
    write_vector(d, "cred-input-sse", s, "anthropic", "sse", MODEL_A,
                 [exp_intent("toolu_12Cr3d3nt14lSh4p3s00", "Bash", "sandbox", J(i12))],
                 markers=["AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EX"])


# ------------------------------------------------------------------
# OpenAI Responses wire builders (pinned docs: response.created,
# response.output_item.added/done, function_call_arguments.delta/done,
# response.completed)

MODEL_O = "gpt-5.2-2025-12-11"


def oev(name, data):
    d = dict(data)
    d.setdefault("type", name)
    d.setdefault("sequence_number", 0)
    return "event: " + name + "\ndata: " + J(d) + "\n\n"


def o_created(model=MODEL_O):
    return oev("response.created", {
        "response": {"id": "resp_01", "object": "response", "status": "in_progress",
                     "model": model, "output": []}})


def o_completed():
    return oev("response.completed", {
        "response": {"id": "resp_01", "object": "response", "status": "completed",
                     "model": MODEL_O,
                     "output": [], "usage": {"input_tokens": 10, "output_tokens": 20}}})


def o_item_added(idx, item):
    return oev("response.output_item.added", {"output_index": idx, "item": item})


def o_item_done(idx, item):
    return oev("response.output_item.done", {"output_index": idx, "item": item})


def o_args_delta(idx, delta, item_id):
    return oev("response.function_call_arguments.delta",
               {"output_index": idx, "item_id": item_id, "delta": delta})


def o_args_done(idx, args, item_id):
    return oev("response.function_call_arguments.done",
               {"output_index": idx, "item_id": item_id, "arguments": args})


def o_call_stream(idx, fc_id, name, args, frags=3, kind="function_call",
                  via_done=False):
    """SSE for one output item; function calls stream arguments in
    deltas (or via a single .done when via_done)."""
    item = {"type": kind, "id": "fc_" + fc_id, "call_id": "call_" + fc_id,
            "name": name, "status": "in_progress", "arguments": ""}
    out = o_item_added(idx, item)
    if via_done:
        out += o_args_done(idx, args, "fc_" + fc_id)
    else:
        step = max(1, (len(args) + frags - 1) // frags) or 1
        for i in range(0, len(args), step):
            out += o_args_delta(idx, args[i:i + step], "fc_" + fc_id)
    item = dict(item)
    item["status"] = "completed"
    item["arguments"] = args
    out += o_item_done(idx, item)
    return out


def o_text_stream(idx, text, item_id):
    return (o_item_added(idx, {"type": "message", "id": item_id, "role": "assistant",
                               "status": "in_progress", "content": []})
            + oev("response.output_text.delta",
                  {"output_index": idx, "item_id": item_id, "content_index": 0,
                   "delta": text})
            + o_item_done(idx, {"type": "message", "id": item_id, "role": "assistant",
                                "status": "completed",
                                "content": [{"type": "output_text", "text": text,
                                             "annotations": []}]}))


def o_json_body(output_items, model=MODEL_O):
    return J({"id": "resp_01", "object": "response", "status": "completed",
              "model": model, "output": output_items,
              "usage": {"input_tokens": 10, "output_tokens": 20}})


def gen_responses():
    d = "openai"
    a1 = {"path": "/tmp/x", "recursive": True}
    a1s = J(a1)
    iid1 = "call_0R3spS1ngl3C4ll0000001"

    write_vector(d, "resp-single-sse",
                 o_created() + o_call_stream(0, "0R3spS1ngl3C4ll0000001", "read_file", a1s)
                 + o_completed(),
                 "responses", "sse", MODEL_O,
                 [exp_intent(iid1, "read_file", "sandbox", a1s)])
    write_vector(d, "resp-single-json",
                 o_json_body([{"type": "function_call", "id": "fc_0R3spS1ngl3C4ll0000001",
                               "call_id": iid1, "name": "read_file",
                               "arguments": a1s, "status": "completed"}]),
                 "responses", "json", MODEL_O,
                 [exp_intent(iid1, "read_file", "sandbox", a1s)])

    # several calls + interleaved output text
    cA = ("call_0R3spMult1C4ll000000a", "run", {"cmd": "make test"})
    cB = ("call_0R3spMult1C4ll000000b", "fetch", {"url": "https://ex.test"})
    s = (o_created()
         + o_text_stream(0, "Working " + MARK + "-o", "msg_0")
         + o_call_stream(1, "0R3spMult1C4ll000000a", cA[1], J(cA[2]))
         + o_call_stream(2, "0R3spMult1C4ll000000b", cB[1], J(cB[2]))
         + o_completed())
    write_vector(d, "resp-multi-sse", s, "responses", "sse", MODEL_O,
                 [exp_intent(cA[0], cA[1], "sandbox", J(cA[2])),
                  exp_intent(cB[0], cB[1], "sandbox", J(cB[2]))],
                 markers=["Working " + MARK + "-o"])

    # arguments in many fragments
    a3 = {"data": "x" * 120, "k": 7}
    s = o_created() + o_call_stream(0, "0R3spFr4gm3nt3dArgs000", "put", J(a3),
                                    frags=37) + o_completed()
    write_vector(d, "resp-fragments-sse", s, "responses", "sse", MODEL_O,
                 [exp_intent("call_0R3spFr4gm3nt3dArgs000", "put", "sandbox", J(a3))])

    # empty arguments
    s = (o_created() + o_item_added(0, {"type": "function_call", "id": "fc_e",
                                        "call_id": "call_0R3spEmptyArgs000000",
                                        "name": "ping", "status": "in_progress",
                                        "arguments": ""})
         + o_item_done(0, {"type": "function_call", "id": "fc_e",
                           "call_id": "call_0R3spEmptyArgs000000", "name": "ping",
                           "status": "completed", "arguments": ""})
         + o_completed())
    write_vector(d, "resp-empty-args-sse", s, "responses", "sse", MODEL_O,
                 [exp_intent("call_0R3spEmptyArgs000000", "ping", "sandbox", "")])
    write_vector(d, "resp-empty-args-json",
                 o_json_body([{"type": "function_call", "id": "fc_e",
                               "call_id": "call_0R3spEmptyArgs000000", "name": "ping",
                               "status": "completed", "arguments": ""}]),
                 "responses", "json", MODEL_O,
                 [exp_intent("call_0R3spEmptyArgs000000", "ping", "sandbox", "")])

    # 1 MiB arguments
    bigarg = J({"payload": "y" * (1 << 20)})
    s = o_created() + o_call_stream(0, "0R3spL4rg3ArgsOn3MiB00", "blob", bigarg,
                                    frags=64) + o_completed()
    write_vector(d, "resp-large-args-sse", s, "responses", "sse", MODEL_O,
                 [exp_intent("call_0R3spL4rg3ArgsOn3MiB00", "blob", "sandbox", bigarg)])

    # provider-hosted calls
    ws = {"type": "web_search_call", "id": "ws_0H0st3dW3bS34rch00",
          "status": "completed",
          "action": {"type": "search", "query": "jcs canonicalization"}}
    fs = {"type": "file_search_call", "id": "fs_0H0st3dF1l3S34rch0",
          "status": "completed", "queries": ["quarterly numbers"], "results": []}
    cc = {"type": "computer_call", "id": "cu_0H0st3dC0mput3rC4ll",
          "call_id": "call_0H0st3dC0mput3rC4ll", "status": "completed",
          "action": {"type": "click", "x": 10, "y": 20}}
    s = (o_created()
         + o_item_added(0, dict(ws, status="in_progress")) + o_item_done(0, ws)
         + o_item_added(1, dict(fs, status="in_progress")) + o_item_done(1, fs)
         + o_item_added(2, dict(cc, status="in_progress")) + o_item_done(2, cc)
         + o_completed())
    write_vector(d, "resp-hosted-sse", s, "responses", "sse", MODEL_O, [
        exp_intent("ws_0H0st3dW3bS34rch00", "web_search_call", "provider",
                   J(ws["action"])),
        exp_intent("fs_0H0st3dF1l3S34rch0", "file_search_call", "provider",
                   J(fs)),  # no arguments/input/action member → item itself
        exp_intent("call_0H0st3dC0mput3rC4ll", "computer_call", "provider",
                   J(cc["action"])),
    ])

    # unknown events + unknown item types ignored
    a8 = {"ok": 1}
    s = (o_created()
         + oev("response.quantum_phase", {"phase": "superposed"})
         + o_item_added(0, {"type": "plasma_call", "id": "pl_1", "status": "in_progress"})
         + o_item_done(0, {"type": "plasma_call", "id": "pl_1", "status": "completed"})
         + o_call_stream(1, "0R3spUnkn0wnTyp3s00000", "run", J(a8))
         + o_completed())
    write_vector(d, "resp-unknown-sse", s, "responses", "sse", MODEL_O,
                 [exp_intent("call_0R3spUnkn0wnTyp3s00000", "run", "sandbox", J(a8))])

    # provider error event mid-stream
    a9 = {"e": 2}
    s = (o_created()
         + o_call_stream(0, "0R3spErr0rM1dStr34m00", "run", J(a9))
         + oev("error", {"code": "server_error", "message": "backend exploded",
                         "param": None}))
    write_vector(d, "resp-error-sse", s, "responses", "sse", MODEL_O,
                 [exp_intent("call_0R3spErr0rM1dStr34m00", "run", "sandbox", J(a9))],
                 unparsed=True, detail_sub="error")

    # stream cut mid-item (deltas arrive, no done)
    s = (o_created()
         + o_item_added(0, {"type": "function_call", "id": "fc_c",
                            "call_id": "call_0R3spCutM1dIt3m0000",
                            "name": "run", "status": "in_progress", "arguments": ""})
         + o_args_delta(0, J({"x": "cut"})[:8], "fc_c"))
    write_vector(d, "resp-cut-sse", s, "responses", "sse", MODEL_O, [],
                 unparsed=True, detail_sub="cut")

    # text-only JSON
    write_vector(d, "resp-text-json",
                 o_json_body([{"type": "message", "id": "msg_t", "role": "assistant",
                               "status": "completed",
                               "content": [{"type": "output_text",
                                            "text": "hi " + MARK + "-oj",
                                            "annotations": []}]}]),
                 "responses", "json", MODEL_O, [], markers=["hi " + MARK + "-oj"])


# ------------------------------------------------------------------
# OpenAI Chat Completions wire builders (pinned docs: streamed chunks
# choices[].delta.tool_calls[index]{id,type,function{name,arguments}},
# finish_reason "tool_calls", then [DONE]).

def cev(data):
    return "data: " + J(data) + "\n\n"


def c_chunk(model, choices, cid="chatcmpl-01"):
    return cev({"id": cid, "object": "chat.completion.chunk",
                "created": 1700000000, "model": model, "choices": choices})


def c_tool_delta(idx, tcidx, **kw):
    tc = {"index": tcidx}
    tc.update(kw)
    return {"index": idx, "delta": {"tool_calls": [tc]}, "finish_reason": None}


def c_finish(idx, reason="tool_calls"):
    return {"index": idx, "delta": {}, "finish_reason": reason}


def c_call_stream(idx, call_id, name, args, frags=3, tcidx=0, model=MODEL_O):
    """Chunks assembling one tool_call at position tcidx."""
    out = c_chunk(model, [c_tool_delta(idx, tcidx, id=call_id, type="function",
                                       function={"name": name, "arguments": ""})])
    step = max(1, (len(args) + frags - 1) // frags) or 1
    for i in range(0, len(args), step):
        out += c_chunk(model, [c_tool_delta(idx, tcidx, function={
            "arguments": args[i:i + step]})])
    return out


def c_json_body(tool_calls, model=MODEL_O):
    return J({"id": "chatcmpl-01", "object": "chat.completion",
              "created": 1700000000, "model": model,
              "choices": [{"index": 0, "finish_reason": "tool_calls",
                           "message": {"role": "assistant", "content": None,
                                       "tool_calls": tool_calls}}],
              "usage": {"prompt_tokens": 10, "completion_tokens": 20,
                        "total_tokens": 30}})


def gen_chat():
    d = "openai"
    a1 = {"cmd": "ls"}
    a1s = J(a1)

    write_vector(d, "chat-single-sse",
                 c_call_stream(0, "call_0Ch4tS1ngl3C4ll000001", "run", a1s)
                 + c_chunk(MODEL_O, [c_finish(0)]) + "data: [DONE]\n\n",
                 "chat", "sse", MODEL_O,
                 [exp_intent("call_0Ch4tS1ngl3C4ll000001", "run", "sandbox", a1s)])
    write_vector(d, "chat-single-json",
                 c_json_body([{"id": "call_0Ch4tS1ngl3C4ll000001", "type": "function",
                               "function": {"name": "run", "arguments": a1s}}]),
                 "chat", "json", MODEL_O,
                 [exp_intent("call_0Ch4tS1ngl3C4ll000001", "run", "sandbox", a1s)])

    # several calls, JSON
    c2 = [("call_0Ch4tMult1C4ll000000a", "run", {"cmd": "a"}),
          ("call_0Ch4tMult1C4ll000000b", "fetch", {"url": "https://e.test"})]
    write_vector(d, "chat-multi-json",
                 c_json_body([{"id": iid, "type": "function",
                               "function": {"name": n, "arguments": J(a)}}
                              for iid, n, a in c2]),
                 "chat", "json", MODEL_O,
                 [exp_intent(iid, n, "sandbox", J(a)) for iid, n, a in c2])

    # two calls' argument fragments interleaved by index (C8.2.2): the
    # wire interleaves deltas of index 0 and index 1; assembly is by
    # index, not arrival.
    argsA = J({"cmd": "sleep 1"})
    argsB = J({"url": "https://x.test", "n": 2})
    s = c_chunk(MODEL_O, [
        c_tool_delta(0, 0, id="call_0Ch4tInt3rL34v3dC4llA", type="function",
                     function={"name": "run", "arguments": ""}),
        c_tool_delta(0, 1, id="call_0Ch4tInt3rL34v3dC4llB", type="function",
                     function={"name": "fetch", "arguments": ""})])
    ha = max(1, len(argsA) // 3)
    hb = max(1, len(argsB) // 3)
    pa = [argsA[i:i + ha] for i in range(0, len(argsA), ha)]
    pb = [argsB[i:i + hb] for i in range(0, len(argsB), hb)]
    for i in range(max(len(pa), len(pb))):
        ch = []
        if i < len(pa):
            ch.append(c_tool_delta(0, 0, function={"arguments": pa[i]}))
        if i < len(pb):
            ch.append(c_tool_delta(0, 1, function={"arguments": pb[i]}))
        s += c_chunk(MODEL_O, ch)
    s += c_chunk(MODEL_O, [c_finish(0)]) + "data: [DONE]\n\n"
    write_vector(d, "chat-interleaved-sse", s, "chat", "sse", MODEL_O,
                 [exp_intent("call_0Ch4tInt3rL34v3dC4llA", "run", "sandbox", argsA),
                  exp_intent("call_0Ch4tInt3rL34v3dC4llB", "fetch", "sandbox", argsB)])

    # many argument fragments
    a4 = {"pad": "q" * 64}
    s = (c_call_stream(0, "call_0Ch4tFr4gm3nts000000", "run", J(a4), frags=31)
         + c_chunk(MODEL_O, [c_finish(0)]) + "data: [DONE]\n\n")
    write_vector(d, "chat-fragments-sse", s, "chat", "sse", MODEL_O,
                 [exp_intent("call_0Ch4tFr4gm3nts000000", "run", "sandbox", J(a4))])

    # empty arguments
    write_vector(d, "chat-empty-args-json",
                 c_json_body([{"id": "call_0Ch4tEmptyArgs0000000", "type": "function",
                               "function": {"name": "ping", "arguments": ""}}]),
                 "chat", "json", MODEL_O,
                 [exp_intent("call_0Ch4tEmptyArgs0000000", "ping", "sandbox", "")])

    # unknown fields/shapes tolerated: extra choices fields, empty deltas
    a6 = {"k": "v"}
    s = (c_chunk(MODEL_O, [{"index": 0, "delta": {"role": "assistant"},
                            "finish_reason": None}])
         + c_chunk(MODEL_O, [{"index": 0, "delta": {"content": None,
                                                  "what": "extra"},
                              "finish_reason": None}])
         + c_call_stream(0, "call_0Ch4tUnkn0wnF13lds000", "run", J(a6))
         + c_chunk(MODEL_O, [c_finish(0)]) + "data: [DONE]\n\n")
    write_vector(d, "chat-unknown-sse", s, "chat", "sse", MODEL_O,
                 [exp_intent("call_0Ch4tUnkn0wnF13lds000", "run", "sandbox", J(a6))])

    # error chunk after a completed call: the finish_reason already
    # landed, so the declaration stands and the error is a stream fault.
    s = (c_call_stream(0, "call_0Ch4tErr0rM1dStr34m0", "run", J({"e": 1}))
         + c_chunk(MODEL_O, [c_finish(0)])
         + cev({"error": {"type": "server_error", "code": "internal",
                          "message": "boom", "param": None}}))
    write_vector(d, "chat-error-sse", s, "chat", "sse", MODEL_O,
                 [exp_intent("call_0Ch4tErr0rM1dStr34m0", "run", "sandbox", J({"e": 1}))],
                 unparsed=True, detail_sub="error")

    # stream cut inside a tool_call (no finish_reason)
    s = (c_chunk(MODEL_O, [c_tool_delta(0, 0, id="call_0Ch4tCutM1dC4ll0000",
                                        type="function",
                                        function={"name": "run", "arguments": ""})])
         + c_chunk(MODEL_O, [c_tool_delta(0, 0, function={
             "arguments": J({"cmd": "cut"})[:6]})]))
    write_vector(d, "chat-cut-sse", s, "chat", "sse", MODEL_O, [],
                 unparsed=True, detail_sub="cut")


# ------------------------------------------------------------------
# Tracking corpus (M8.3): scripted request/response pairs replayed
# through the real broker. Each scenario:
#   {"endpoint": "anthropic"|"responses"|"chat",
#    "max_intent_open_seconds": <policy value the test sets>,
#    "steps": [{"name": str,
#               "request": <request body object>,
#               "response": <response body object>}],
#    "markers": [...]}
# "response" is either {"sse": "<wire text>"} or {"json": <object>}.
# Expected records land in <name>.expected.json — digests computed here.

TD = "tracking"


def anth_req(model, messages, system=None):
    b = {"model": model, "max_tokens": 1024, "messages": messages}
    if system is not None:
        b["system"] = system
    return b


def anth_resp_sse(iid, tool, inp, text=None):
    s = a_msg_start()
    idx = 0
    if text is not None:
        s += a_text_stream(text, idx)
        idx += 1
    s += a_tool_stream(iid, tool, inp, idx=idx)
    s += a_msg_end()
    return {"sse": s}


def anth_resp_text_sse(text):
    return {"sse": a_msg_start() + a_text_stream(text, 0)
            + a_msg_end(stop="end_turn")}


def anth_msg(role, content):
    return {"role": role, "content": content}


def anth_tool_result(iid, content, is_error=None):
    b = {"type": "tool_result", "tool_use_id": iid, "content": content}
    if is_error is not None:
        b["is_error"] = is_error
    return b


def anth_tool_use(iid, tool, inp):
    return {"type": "tool_use", "id": iid, "name": tool, "input": inp}


def ctx_blocks_anthropic(req):
    """Mirror of ParseRequest's block enumeration for anthropic bodies:
    system (string→1 | array→each), then each message's content blocks
    (string→1 | array→each). Each entry's digest is the canonical sha of
    the block's own transmitted serialization."""
    out = []

    def add(role, kind, raw, intent_id):
        out.append({"index": len(out), "role": role, "kind": kind,
                    "sha256": canon_sha256(raw),
                    "len": len(J(raw).encode("utf-8")),
                    "intent_id": intent_id})

    sysm = req.get("system")
    if sysm is not None:
        if isinstance(sysm, list):
            for p in sysm:
                add("system", "text", p, "")
        else:
            add("system", "text", sysm, "")
    for m in req["messages"]:
        c = m.get("content")
        if c is None:
            continue
        if isinstance(c, str):
            add(m["role"], "text", c, "")
        elif isinstance(c, list):
            for b in c:
                kind = b.get("type", "unknown") if isinstance(b, dict) else "part"
                iid = ""
                if isinstance(b, dict):
                    if kind == "tool_result":
                        iid = b.get("tool_use_id", "")
                    elif kind in ("tool_use", "server_tool_use"):
                        iid = b.get("id", "")
                add(m["role"], kind, b, iid)
    return out


def result_refs_anthropic(req):
    out = []
    for m in req["messages"]:
        c = m.get("content")
        if isinstance(c, list):
            for b in c:
                if isinstance(b, dict) and b.get("type") == "tool_result":
                    content = b.get("content")
                    if content is None:
                        sha, ln, has = "", 0, False
                    elif isinstance(content, str):
                        sha = hashlib.sha256(content.encode()).hexdigest()
                        ln, has = len(content.encode()), True
                    else:
                        sha = canon_sha256(content)
                        ln, has = len(J(content).encode()), True
                    out.append({
                        "intent_id": b.get("tool_use_id", ""),
                        "content_sha256": sha, "content_len": ln,
                        "has_content": has,
                        "is_error": b.get("is_error")})
    return out


def write_scenario(name, endpoint, steps, expect, max_open=None, markers=()):
    finalize_context(expect, steps)
    sc = {"endpoint": endpoint, "steps": steps,
          "markers": list(markers)}
    if max_open is not None:
        sc["max_intent_open_seconds"] = max_open
    with open(os.path.join(ROOT, TD, name + ".scenario.json"), "w") as f:
        json.dump(sc, f, indent=2)
        f.write("\n")
    with open(os.path.join(ROOT, TD, name + ".expected.json"), "w") as f:
        json.dump(expect, f, indent=2)
        f.write("\n")


def track_step(name, req, resp):
    return {"name": name, "request": req, "response": resp}


def expected_records():
    return {"declared": [], "results": [], "context": [], "unparsed": []}


def finalize_context(exp, steps):
    """Recompute context.observed truth for a whole scenario: unique
    block digests in first-seen order, running block_count and
    context_sha256 (SHA-256 of the JSON array of digest strings)."""
    seen = []
    exp["context"] = []
    for i, st in enumerate(steps):
        fresh = []
        for b in ctx_blocks_anthropic(st["request"]):
            if b["sha256"] in seen:
                continue
            seen.append(b["sha256"])
            fresh.append(b)
        ctx_sha = ""
        if seen:
            ctx_sha = hashlib.sha256(
                ("[" + ",".join('"' + x + '"' for x in seen) + "]")
                .encode()).hexdigest()
        exp["context"].append({"step": i, "new_blocks": fresh,
                               "block_count": len(seen),
                               "context_sha256": ctx_sha})
    return exp


def gen_tracking():
    mdl = MODEL_A

    # --- sequential: declare A → result A + declare B → result B ----
    exp = expected_records()
    reqA = anth_req(mdl, [anth_msg("user", "list files " + MARK + "-q")])
    exp["declared"].append({"step": 0, "intent_id": "toolu_seq_A",
                            "tool": "Bash", "executor": "sandbox",
                            "input_sha256": canon_sha256({"command": "ls"}),
                            "input_len": len(J({"command": "ls"}))})
    reqB = anth_req(mdl, [
        anth_msg("user", "list files " + MARK + "-q"),
        anth_msg("assistant", [anth_tool_use("toolu_seq_A", "Bash", {"command": "ls"})]),
        anth_msg("user", [anth_tool_result("toolu_seq_A", "f1\nf2 " + MARK + "-r")]),
    ])
    exp["results"].append({"step": 1, "intent_id": "toolu_seq_A",
                           "closed_by": "tool_result",
                           **result_refs_anthropic(reqB)[0]})
    exp["declared"].append({"step": 1, "intent_id": "toolu_seq_B",
                            "tool": "Read", "executor": "sandbox",
                            "input_sha256": canon_sha256({"file_path": "/tmp/f1"}),
                            "input_len": len(J({"file_path": "/tmp/f1"}))})
    reqC = anth_req(mdl, [
        anth_msg("user", "list files " + MARK + "-q"),
        anth_msg("assistant", [anth_tool_use("toolu_seq_A", "Bash", {"command": "ls"})]),
        anth_msg("user", [anth_tool_result("toolu_seq_A", "f1\nf2 " + MARK + "-r")]),
        anth_msg("assistant", [anth_tool_use("toolu_seq_B", "Read", {"file_path": "/tmp/f1"})]),
        anth_msg("user", [anth_tool_result("toolu_seq_B", "data " + MARK + "-r2")]),
    ])
    exp["results"].append({"step": 2, "intent_id": "toolu_seq_B",
                           "closed_by": "tool_result",
                           **result_refs_anthropic(reqC)[-1]})
    write_scenario("sequential", "anthropic", [
        track_step("t1", reqA, anth_resp_sse("toolu_seq_A", "Bash", {"command": "ls"})),
        track_step("t2", reqB, anth_resp_sse("toolu_seq_B", "Read", {"file_path": "/tmp/f1"})),
        track_step("t3", reqC, anth_resp_text_sse("done " + MARK + "-end")),
    ], exp, markers=[MARK + "-q", MARK + "-r", MARK + "-r2", MARK + "-end"])

    # --- parallel results answered in a different order -------------
    exp = expected_records()
    calls = [("toolu_par_A", "Bash", {"command": "a"}),
             ("toolu_par_B", "Bash", {"command": "b"}),
             ("toolu_par_C", "Bash", {"command": "c"})]
    req0 = anth_req(mdl, [anth_msg("user", "run three " + MARK + "-p0")])
    for iid, tool, inp in calls:
        exp["declared"].append({"step": 0, "intent_id": iid, "tool": tool,
                                "executor": "sandbox",
                                "input_sha256": canon_sha256(inp),
                                "input_len": len(J(inp))})
    resp = a_msg_start()
    for k, (iid, tool, inp) in enumerate(calls):
        resp += a_tool_stream(iid, tool, inp, idx=k)
    resp += a_msg_end()
    # results arrive C, then A, then B across two requests
    hist = [anth_msg("user", "run three " + MARK + "-p0"),
            anth_msg("assistant", [anth_tool_use(*c) for c in calls])]
    req1 = anth_req(mdl, hist + [
        anth_msg("user", [anth_tool_result("toolu_par_C", "okC"),
                          anth_tool_result("toolu_par_A", "okA")])])
    for rr in result_refs_anthropic(req1):
        exp["results"].append({"step": 1, "closed_by": "tool_result", **rr})
    req2 = anth_req(mdl, hist + [
        anth_msg("user", [anth_tool_result("toolu_par_C", "okC"),
                          anth_tool_result("toolu_par_A", "okA"),
                          anth_tool_result("toolu_par_B", "okB")])])
    exp["results"].append({"step": 2, "closed_by": "tool_result",
                           **result_refs_anthropic(req2)[-1]})
    write_scenario("parallel-outoforder", "anthropic", [
        track_step("t1", req0, {"sse": resp}),
        track_step("t2", req1, anth_resp_text_sse("two done " + MARK + "-p1")),
        track_step("t3", req2, anth_resp_text_sse("all done " + MARK + "-p2")),
    ], exp, markers=[MARK + "-p0", MARK + "-p1", MARK + "-p2"])

    # --- timeout: declared, never answered; next request sweeps it ---
    exp = expected_records()
    req0 = anth_req(mdl, [anth_msg("user", "wait " + MARK + "-w0")])
    exp["declared"].append({"step": 0, "intent_id": "toolu_tmo_A",
                            "tool": "Bash", "executor": "sandbox",
                            "input_sha256": canon_sha256({"command": "sleep"}),
                            "input_len": len(J({"command": "sleep"}))})
    req1 = anth_req(mdl, [anth_msg("user", "still waiting " + MARK + "-w1")])
    exp["results"].append({"step": 1, "intent_id": "toolu_tmo_A",
                           "closed_by": "timeout"})
    write_scenario("timeout", "anthropic", [
        track_step("t1", req0,
                   anth_resp_sse("toolu_tmo_A", "Bash", {"command": "sleep"})),
        track_step("t2", req1, anth_resp_text_sse("ok " + MARK + "-w2")),
    ], exp, max_open=1, markers=[MARK + "-w0", MARK + "-w1", MARK + "-w2"])

    # --- unknown result id: ignored, no intent.result ---------------
    exp = expected_records()
    req0 = anth_req(mdl, [anth_msg("user", "go " + MARK + "-u0")])
    exp["declared"].append({"step": 0, "intent_id": "toolu_unk_A",
                            "tool": "Bash", "executor": "sandbox",
                            "input_sha256": canon_sha256({"command": "x"}),
                            "input_len": len(J({"command": "x"}))})
    req1 = anth_req(mdl, [
        anth_msg("user", "go " + MARK + "-u0"),
        anth_msg("assistant", [anth_tool_use("toolu_unk_A", "Bash", {"command": "x"}),
                               anth_tool_use("toolu_unk_GHOST", "Bash", {"command": "g"})]),
        anth_msg("user", [anth_tool_result("toolu_unk_A", "a"),
                          anth_tool_result("toolu_unk_GHOST", "ghost")]),
    ])
    exp["results"].append({"step": 1, "intent_id": "toolu_unk_A",
                           "closed_by": "tool_result",
                           **result_refs_anthropic(req1)[0]})
    write_scenario("unknown-result", "anthropic", [
        track_step("t1", req0, anth_resp_sse("toolu_unk_A", "Bash", {"command": "x"})),
        track_step("t2", req1, anth_resp_text_sse("done " + MARK + "-u1")),
    ], exp, markers=[MARK + "-u0", MARK + "-u1"])

    # --- two interleaved conversations ------------------------------
    exp = expected_records()
    convA0 = anth_req(mdl, [anth_msg("user", "conv A " + MARK + "-a0")])
    convB0 = anth_req(mdl, [anth_msg("user", "conv B " + MARK + "-b0")])
    exp["declared"] += [
        {"step": 0, "intent_id": "toolu_ic_A1", "tool": "Bash", "executor": "sandbox",
         "input_sha256": canon_sha256({"command": "aa"}), "input_len": len(J({"command": "aa"}))},
        {"step": 1, "intent_id": "toolu_ic_B1", "tool": "Read", "executor": "sandbox",
         "input_sha256": canon_sha256({"file_path": "/b"}), "input_len": len(J({"file_path": "/b"}))},
        {"step": 3, "intent_id": "toolu_ic_B2", "tool": "Bash", "executor": "sandbox",
         "input_sha256": canon_sha256({"command": "bb"}), "input_len": len(J({"command": "bb"}))},
        {"step": 2, "intent_id": "toolu_ic_A2", "tool": "Bash", "executor": "sandbox",
         "input_sha256": canon_sha256({"command": "ab"}), "input_len": len(J({"command": "ab"}))},
    ]
    convA1 = anth_req(mdl, [
        anth_msg("user", "conv A " + MARK + "-a0"),
        anth_msg("assistant", [anth_tool_use("toolu_ic_A1", "Bash", {"command": "aa"})]),
        anth_msg("user", [anth_tool_result("toolu_ic_A1", "outA")]),
    ])
    convB1 = anth_req(mdl, [
        anth_msg("user", "conv B " + MARK + "-b0"),
        anth_msg("assistant", [anth_tool_use("toolu_ic_B1", "Read", {"file_path": "/b"})]),
        anth_msg("user", [anth_tool_result("toolu_ic_B1", "outB")]),
    ])
    convA2 = anth_req(mdl, [
        anth_msg("user", "conv A " + MARK + "-a0"),
        anth_msg("assistant", [anth_tool_use("toolu_ic_A1", "Bash", {"command": "aa"})]),
        anth_msg("user", [anth_tool_result("toolu_ic_A1", "outA")]),
        anth_msg("assistant", [anth_tool_use("toolu_ic_A2", "Bash", {"command": "ab"})]),
        anth_msg("user", [anth_tool_result("toolu_ic_A2", "outA2")]),
    ])
    convB2 = anth_req(mdl, [
        anth_msg("user", "conv B " + MARK + "-b0"),
        anth_msg("assistant", [anth_tool_use("toolu_ic_B1", "Read", {"file_path": "/b"})]),
        anth_msg("user", [anth_tool_result("toolu_ic_B1", "outB")]),
        anth_msg("assistant", [anth_tool_use("toolu_ic_B2", "Bash", {"command": "bb"})]),
        anth_msg("user", [anth_tool_result("toolu_ic_B2", "outB2")]),
    ])
    exp["results"] = [
        {"step": 2, "closed_by": "tool_result", **result_refs_anthropic(convA1)[0]},
        {"step": 3, "closed_by": "tool_result", **result_refs_anthropic(convB1)[0]},
        {"step": 4, "closed_by": "tool_result", **result_refs_anthropic(convA2)[-1]},
        {"step": 5, "closed_by": "tool_result", **result_refs_anthropic(convB2)[-1]},
    ]
    write_scenario("interleaved-conversations", "anthropic", [
        track_step("A1", convA0, anth_resp_sse("toolu_ic_A1", "Bash", {"command": "aa"})),
        track_step("B1", convB0, anth_resp_sse("toolu_ic_B1", "Read", {"file_path": "/b"})),
        track_step("A2", convA1, anth_resp_sse("toolu_ic_A2", "Bash", {"command": "ab"})),
        track_step("B2", convB1, anth_resp_sse("toolu_ic_B2", "Bash", {"command": "bb"})),
        track_step("A3", convA2, anth_resp_text_sse("finA")),
        track_step("B3", convB2, anth_resp_text_sse("finB")),
    ], exp, markers=[MARK + "-a0", MARK + "-b0"])

    # --- same result resent in every later request: closes once -----
    exp = expected_records()
    req0 = anth_req(mdl, [anth_msg("user", "resend " + MARK + "-s0")])
    exp["declared"].append({"step": 0, "intent_id": "toolu_rsnd_A",
                            "tool": "Bash", "executor": "sandbox",
                            "input_sha256": canon_sha256({"command": "r"}),
                            "input_len": len(J({"command": "r"}))})
    tr = anth_tool_result("toolu_rsnd_A", "first " + MARK + "-s1")
    msgs = [anth_msg("user", "resend " + MARK + "-s0"),
            anth_msg("assistant", [anth_tool_use("toolu_rsnd_A", "Bash", {"command": "r"})]),
            anth_msg("user", [tr])]
    req1 = anth_req(mdl, msgs)
    exp["results"].append({"step": 1, "closed_by": "tool_result",
                           **result_refs_anthropic(req1)[0]})
    req2 = anth_req(mdl, msgs + [anth_msg("assistant", [{"type": "text",
                                                        "text": "noted"}])])
    req3 = anth_req(mdl, msgs + [anth_msg("assistant", [{"type": "text",
                                                        "text": "noted"}]),
                                  anth_msg("user", "more " + MARK + "-s2")])
    write_scenario("resend-result", "anthropic", [
        track_step("t1", req0, anth_resp_sse("toolu_rsnd_A", "Bash", {"command": "r"})),
        track_step("t2", req1, anth_resp_text_sse("noted")),
        track_step("t3", req2, anth_resp_text_sse("still noted")),
        track_step("t4", req3, anth_resp_text_sse("again")),
    ], exp, markers=[MARK + "-s0", MARK + "-s1", MARK + "-s2"])

    # --- compaction: a 50-turn conversation; after turn 25 the client
    #     truncates the earliest blocks. context.observed keeps
    #     first-seen digests; resent old blocks never re-emit; the
    #     truncated request has FEWER context blocks yet no re-record. -
    exp = expected_records()
    steps = []
    hist = []

    for t in range(50):
        iid = "toolu_c%02d" % t
        inp = {"command": "turn-%d" % t}
        if t == 0:
            req = anth_req(mdl, [anth_msg("user", "turn 0 " + MARK + "-f0")])
        else:
            msgs = list(hist)
            if t > 25:
                # compaction: the client drops everything before the
                # 10 most recent messages and prefixes a summary
                msgs = [anth_msg("user", "summary so far " + MARK + "-sm")] \
                    + hist[-10:]
            msgs.append(anth_msg("user", "turn %d" % t))
            req = anth_req(mdl, msgs)
        stepno = len(steps)
        exp["declared"].append({"step": stepno, "intent_id": iid,
                                "tool": "Bash", "executor": "sandbox",
                                "input_sha256": canon_sha256(inp),
                                "input_len": len(J(inp))})
        resp = anth_resp_sse(iid, "Bash", inp)
        steps.append(track_step("t%d" % (stepno + 1), req, resp))
        # next request carries the result
        result = anth_tool_result(iid, "out-%d" % t)
        hist.append(anth_msg("assistant", [anth_tool_use(iid, "Bash", inp)]))
        hist.append(anth_msg("user", [result]))
        reqn = dict(req)
        nmsgs = (list(hist[-12:]) if t > 25 else list(hist))
        if t > 25:
            nmsgs = [anth_msg("user", "summary so far " + MARK + "-sm")] + nmsgs
        reqn = anth_req(mdl, nmsgs + [anth_msg("user", "ack %d" % t)])
        rr = result_refs_anthropic(reqn)
        exp["results"].append({"step": len(steps), "closed_by": "tool_result",
                               **rr[-1]})
        steps.append(track_step("a%d" % (stepno + 1), reqn,
                                anth_resp_text_sse("ok %d" % t)))
    write_scenario("fifty-turn", "anthropic", steps, exp)


def main():
    gen_anthropic()
    gen_responses()
    gen_chat()
    gen_tracking()
    n = 0
    for dd in ("anthropic", "openai", "tracking"):
        for f in sorted(os.listdir(os.path.join(ROOT, dd))):
            if f.endswith((".sse", ".json")) and not f.endswith("expected.json") \
                    and not f.endswith("scenario.json"):
                n += 1
            elif f.endswith(".scenario.json"):
                n += 1
    print("wrote %d vectors under %s" % (n, ROOT))


if __name__ == "__main__":
    main()
