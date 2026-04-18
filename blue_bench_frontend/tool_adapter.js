/**
 * Tool schema + response adapters used by `loop.js`.
 *
 *   - MCP tool-list → Ollama / Anthropic schema
 *   - MCP tool-call result → flat text (parity with the Python client)
 *   - Text-embedded tool-call parser (fenced, legacy tags, bare JSON)
 *   - Ollama NDJSON stream reader
 *   - Anthropic SSE stream reader (text + tool_use blocks)
 *
 * Kept separate so `loop.js` stays within its line budget and the parsers can
 * be unit-tested on their own.
 *
 * @module tool_adapter
 */

// ---- schema conversion ---------------------------------------------------

/**
 * Convert MCP `tools/list` entries into Ollama's chat tool schema.
 * @param {Array<{ name: string, description?: string, inputSchema?: object }>} tools
 */
export function toOllamaTools(tools) {
    return tools.map((t) => ({
        type: "function",
        function: {
            name: t.name,
            description: t.description ?? "",
            parameters: t.inputSchema ?? { type: "object", properties: {} },
        },
    }));
}

/**
 * Convert MCP `tools/list` entries into Anthropic's tool schema.
 * @param {Array<{ name: string, description?: string, inputSchema?: object }>} tools
 */
export function toAnthropicTools(tools) {
    return tools.map((t) => ({
        name: t.name,
        description: t.description ?? "",
        input_schema: t.inputSchema ?? { type: "object", properties: {} },
    }));
}

// ---- result flattening ---------------------------------------------------

/**
 * Concatenate MCP tool-result content blocks into a single text string,
 * mirroring the Python client's `call_tool()` shape.
 * @param {{ content?: Array<{ type: string, text?: string }>, isError?: boolean } | string} result
 * @returns {string}
 */
export function flattenToolResult(result) {
    if (typeof result === "string") return result;
    if (!result || !Array.isArray(result.content)) return "";
    const parts = [];
    for (const block of result.content) {
        if (block && typeof block.text === "string") parts.push(block.text);
    }
    return parts.join("\n");
}

// ---- text-embedded tool-call parser --------------------------------------

const TOOL_FENCE_RE = /```tool_(?:call|code)\s*\n([\s\S]*?)\n\s*```/g;
const TOOL_TAG_RE = /<tool>([\w_]+)<\/tool>(?:\s*<args>(\{[\s\S]*?\})<\/args>)?/g;
const BARE_JSON_NAME_RE = /\{\s*"name"\s*:\s*"([\w_]+)"/g;

/** @param {string} raw */
function fixJsonQuirks(raw) {
    return raw.trim().replace(/,\s*([}\]])/g, "$1");
}

/**
 * Extract bracket-balanced `{"name": ..., ...}` objects.
 * @param {string} text
 * @returns {Array<{ name: string, raw: string }>}
 */
function extractJsonToolCalls(text) {
    const out = [];
    BARE_JSON_NAME_RE.lastIndex = 0;
    let m;
    while ((m = BARE_JSON_NAME_RE.exec(text)) !== null) {
        const start = m.index;
        let depth = 0, inStr = false, esc = false;
        for (let i = start; i < text.length; i++) {
            const ch = text[i];
            if (inStr) {
                if (esc) esc = false;
                else if (ch === "\\") esc = true;
                else if (ch === '"') inStr = false;
            } else {
                if (ch === '"') inStr = true;
                else if (ch === "{") depth += 1;
                else if (ch === "}") {
                    depth -= 1;
                    if (depth === 0) { out.push({ name: m[1], raw: text.slice(start, i + 1) }); break; }
                }
            }
        }
    }
    return out;
}

/**
 * Parse every tool call from a text-embedded response. Tries fenced, then
 * legacy tags, then bare JSON — same precedence as `runner.py`.
 * @param {string} content
 * @returns {Array<{ name: string, args: Record<string, unknown> }>}
 */
export function parseTextEmbeddedToolCalls(content) {
    /** @type {Array<{ name: string, args: any }>} */
    const calls = [];

    TOOL_FENCE_RE.lastIndex = 0;
    let m;
    while ((m = TOOL_FENCE_RE.exec(content)) !== null) {
        const raw = fixJsonQuirks(m[1]);
        let obj;
        try { obj = JSON.parse(raw); } catch { continue; }
        const name = obj.name ?? "";
        let args = obj.parameters ?? obj.arguments ?? {};
        if (typeof args === "string") { try { args = JSON.parse(args); } catch { args = {}; } }
        if (name) calls.push({ name, args });
    }

    if (calls.length === 0) {
        TOOL_TAG_RE.lastIndex = 0;
        while ((m = TOOL_TAG_RE.exec(content)) !== null) {
            const name = m[1];
            let args = {};
            if (m[2] != null) { try { args = JSON.parse(fixJsonQuirks(m[2])); } catch { args = {}; } }
            calls.push({ name, args });
        }
    }

    if (calls.length === 0) {
        for (const { name, raw } of extractJsonToolCalls(content)) {
            let args = {};
            try {
                const obj = JSON.parse(fixJsonQuirks(raw));
                args = obj.parameters ?? obj.arguments ?? {};
                if (typeof args === "string") { try { args = JSON.parse(args); } catch { args = {}; } }
            } catch { /* keep empty */ }
            calls.push({ name, args });
        }
    }

    return calls;
}

// ---- Ollama NDJSON reader ------------------------------------------------

/**
 * Read an Ollama streaming chat response. Returns the merged message.
 * @param {Response} res
 * @param {AbortSignal | undefined} signal
 * @returns {Promise<{ message: { content: string, tool_calls?: Array<any> }, done: boolean }>}
 */
export async function readOllamaStream(res, signal) {
    if (!res.ok) {
        let body = "";
        try { body = await res.text(); } catch { /* ignore */ }
        throw new Error(`Ollama HTTP ${res.status}${body ? ` — ${body}` : ""}`);
    }
    if (!res.body) {
        const obj = await res.json();
        return { message: obj.message ?? { content: "" }, done: true };
    }
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    let content = "";
    /** @type {Array<any>} */
    let toolCalls = [];
    let done = false;
    try {
        // eslint-disable-next-line no-constant-condition
        while (true) {
            if (signal?.aborted) throw new DOMException("aborted", "AbortError");
            const { value, done: d } = await reader.read();
            if (d) break;
            buf += decoder.decode(value, { stream: true });
            let nl;
            while ((nl = buf.indexOf("\n")) !== -1) {
                const line = buf.slice(0, nl).trim();
                buf = buf.slice(nl + 1);
                if (!line) continue;
                let obj;
                try { obj = JSON.parse(line); } catch { continue; }
                if (obj.message) {
                    if (typeof obj.message.content === "string") content += obj.message.content;
                    if (Array.isArray(obj.message.tool_calls) && obj.message.tool_calls.length) {
                        toolCalls = toolCalls.concat(obj.message.tool_calls);
                    }
                }
                if (obj.done) done = true;
            }
        }
    } finally {
        try { reader.releaseLock(); } catch { /* ignore */ }
    }
    return { message: { content, tool_calls: toolCalls.length ? toolCalls : undefined }, done };
}

// ---- Anthropic SSE reader ------------------------------------------------

/**
 * Mutate `blocks` in-place from one Anthropic SSE event.
 */
function handleAnthropicEvent(msg, blocks, setStop) {
    const t = msg.type;
    if (t === "content_block_start") {
        const copy = { ...(msg.content_block || {}) };
        if (copy.type === "tool_use") { copy.input = copy.input ?? {}; copy._inputJson = ""; }
        else if (copy.type === "text") copy.text = copy.text ?? "";
        blocks[msg.index] = copy;
        return;
    }
    if (t === "content_block_delta") {
        const b = blocks[msg.index]; if (!b) return;
        const d = msg.delta || {};
        if (d.type === "text_delta") b.text = (b.text || "") + (d.text || "");
        else if (d.type === "input_json_delta") b._inputJson = (b._inputJson || "") + (d.partial_json || "");
        return;
    }
    if (t === "content_block_stop") {
        const b = blocks[msg.index];
        if (b && b.type === "tool_use") {
            try { b.input = b._inputJson ? JSON.parse(b._inputJson) : (b.input || {}); }
            catch { b.input = b.input || {}; }
            delete b._inputJson;
        }
        return;
    }
    if (t === "message_delta" && msg.delta?.stop_reason) setStop(msg.delta.stop_reason);
}

/**
 * Read an Anthropic Messages response — JSON or SSE streaming.
 * @param {Response} res
 * @returns {Promise<{ content: Array<object>, stop_reason: string | null }>}
 */
export async function readAnthropicResponse(res) {
    if (!res.ok) {
        let body = "";
        try { body = await res.text(); } catch { /* ignore */ }
        throw new Error(`Anthropic proxy HTTP ${res.status}${body ? ` — ${body}` : ""}`);
    }
    const ct = res.headers.get("content-type") || "";
    if (!ct.includes("text/event-stream")) return res.json();
    if (!res.body) return res.json();

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    /** @type {Array<any>} */
    const blocks = [];
    let stopReason = null;
    try {
        // eslint-disable-next-line no-constant-condition
        while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            buf += decoder.decode(value, { stream: true });
            let idx;
            while ((idx = buf.indexOf("\n")) !== -1) {
                const line = buf.slice(0, idx);
                buf = buf.slice(idx + 1);
                if (!line || line.startsWith("event:")) continue;
                if (!line.startsWith("data:")) continue;
                const data = line.slice(5).trim();
                if (!data) continue;
                let msg;
                try { msg = JSON.parse(data); } catch { continue; }
                handleAnthropicEvent(msg, blocks, (s) => { stopReason = s; });
            }
        }
    } finally {
        try { reader.releaseLock(); } catch { /* ignore */ }
    }
    return { content: blocks, stop_reason: stopReason };
}
