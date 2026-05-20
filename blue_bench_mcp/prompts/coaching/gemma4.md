## Tool Call Format (Gemma 4 E4B — Native)

Gemma 4 E4B has native function calling. Tool calls travel through the runtime's structured `tool_calls` channel — do not embed JSON tool calls in your prose text.

- {tool_schema_hint}
- Parameter names and types must match the tool's `input_schema` exactly. Use integer literals for integer parameters (not strings like `"1"` or `"Critical"`).
- Omit a parameter to use its default. Do not pass `null`, `"any"`, or empty-string placeholders — those often fail validation.
- **Every assistant turn must have non-empty content.** After tool results arrive, write a brief analysis (1-3 sentences) citing what the output showed, then either call the next tool or produce the final answer. Do not respond with empty text.

## Gemma 4 Known Weaknesses

- **Detection-rule syntax (Phase 1 regression).** When writing Sigma or YARA rules, use only the published schema. Do not invent block names. Do not put literal logical operators (`AND`, `OR`, `NOT`) inside selection bodies — those belong in the `condition` field. Declare required module imports at the top of YARA rules.
- **Argument-type discipline.** Integers stay integers; strings stay strings; optional parameters are omitted, not filled with placeholders. Read the tool's `input_schema` before calling.
- **Host-centric network queries.** When investigating a specific host, you must cover both traffic directions. Use `host_ip` (matches src OR dest in one call) or run `src_ip` and `dest_ip` queries in parallel. Never query only one direction — a host appears as source on outbound traffic and as destination on inbound.
  - ❌ WRONG: `search_alerts(dest_ip="10.10.5.22")` — misses all alerts where 10.10.5.22 is the source
  - ❌ WRONG: `get_connections(dest_ip="10.10.5.22")` — misses all outbound connections from that host
  - ✅ RIGHT (single call): `search_alerts(host_ip="10.10.5.22")` — matches src OR dest, finds everything
  - ✅ RIGHT (parallel): `search_alerts(src_ip="10.10.5.22")` + `search_alerts(dest_ip="10.10.5.22")` in the same turn
- **Timeline queries need a wide timerange.** When building a timeline or investigating an incident, set `timerange_minutes=1440` (24 hours). The default 60-minute window will miss earlier stages of multi-phase attacks. Resolve hostname first via `list_endpoints()`, then query by hostname for EDR and HIDS tools.
- **Scope creep on scoped questions.** When a prompt asks a specific question ("what services are exposed on this host"), answer THAT question first with direct evidence from the right tool. If follow-up investigation surfaces related findings, include them after answering the original question — not in place of it.
- **Preamble-only answers.** Do not produce an "I will check..." response with no investigation. Either call the tool, or if the answer is already clear, produce the final answer directly.
- **Data-source conflicts.** When sources disagree on timestamps or attribution, surface the conflict rather than smoothing it over.
