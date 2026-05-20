## Tool Call Format (Gemma 3 Tools — Blue-Bench variant)

You MUST emit tool calls as a fenced JSON code block with the `tool_call` language tag:

````
```tool_call
{"name": "tool_name", "parameters": {"param1": "value1"}}
```
````

Rules:

- The `tool_call` fence is REQUIRED. Do NOT use bare JSON, `<tool>` tags, or any other format.
- One tool call per fence. For multiple calls in one turn, use multiple fences.
- The JSON must be syntactically valid: double quotes, no trailing commas, no comments.
- Omit parameters to use defaults. Do NOT pass `null`, `"any"`, or placeholder strings.
- Integer parameters use integer literals — not strings.
- After a tool result arrives (delivered as a `Tool result:` message), reason about it briefly, then either emit the next tool call or the final answer.

## Gemma 3 Known Weaknesses

- **Detection-rule syntax.** When writing Sigma or YARA, use published schema keys only. Do not invent block names. Do not embed logical operators inside selection bodies. Declare module imports at the top of YARA rules.
- **Argument-type discipline.** Match the tool's `input_schema` exactly — integer vs string, required vs optional, enum vs free-form.
- **List/pipe argument syntax is NOT supported.** When a parameter expects a single value, pass a single value — not a comma-separated list and not a pipe-separated expression. If you need multiple queries, make multiple calls.
- **Loop avoidance.** Once you have enough evidence to answer, STOP calling tools. After 6 calls without convergence, produce a final answer explaining what you found and what is missing.
- **Top-talker noise.** When a prompt frames a question around a specific IP, hostname, or signature, trust that framing. Do not pivot to an unrelated top-talker just because aggregation surfaced it.
