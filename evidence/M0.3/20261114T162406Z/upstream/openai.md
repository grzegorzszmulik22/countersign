# Upstream check: OpenAI Responses + Chat Completions (06-agent-loop.md §8)

Checked 2026-11-14 against platform.openai.com API reference and the
function-calling guide.

## Responses API

- Request: `POST /v1/responses` `{model, input:[...], tools?, stream?}`.
- Output item (non-streaming and `output_item.done`):
  `{"type":"function_call","id":"fc_...","call_id":"call_...","name":"get_weather","arguments":"{\"location\":\"Paris, France\"}","status":"completed"}`
  — `arguments` is a JSON *string*.
- Streaming events (SSE `event:`/`type`): `response.created`,
  `response.in_progress`, `response.output_item.added`
  (`{item:{type:"function_call",id,call_id,name,arguments:""}, output_index,
  response_id, sequence_number}`), `response.function_call_arguments.delta`
  (`{item_id, output_index, delta:<string fragment>, response_id,
  sequence_number}`), `response.function_call_arguments.done`
  (`{item_id, output_index, arguments:<full string>}`),
  `response.output_item.done`, `response.output_text.delta`,
  `response.content_part.added/.done`, `response.completed`.
- Tool results go back as input items
  `{"type":"function_call_output","call_id":"call_...","output":"..."}`.

## Chat Completions

- Non-streaming: `choices[].message.tool_calls[]` =
  `{"id":"call_...","type":"function","function":{"name":"...","arguments":"<json string>"}}`;
  `finish_reason:"tool_calls"`. Tool results are messages
  `{"role":"tool","tool_call_id":"call_...","content":"..."}`.
- Streaming: `object:"chat.completion.chunk"`;
  `choices[].delta.tool_calls[]` entries carry `index` (position, used to
  assemble interleaved calls), `id`, `type:"function"`, and
  `function:{name, arguments}` where name/id appear on the first chunk and
  `arguments` arrives as string fragments. Stream ends with `data: [DONE]`.
- Bearer auth: `Authorization: Bearer <key>`. Anthropic uses `x-api-key` +
  `anthropic-version` (mockllm records the key used for `/v1/files`).
