/**
 * Pure utility functions for app.js. Split out so they're DOM-free and
 * unit-testable under node:test without jsdom.
 *
 * @module app_utils
 */

/** Default endpoints. Overridable via localStorage. */
export const DEFAULT_ENDPOINTS = Object.freeze({
    mcp:       "http://localhost:8765",
    ollama:    "http://localhost:11434",
    anthropic: "http://localhost:8766",
});

export const STORAGE_KEY = "blue-bench:endpoints";

/**
 * Pull endpoints from localStorage, falling back to DEFAULT_ENDPOINTS on missing
 * or malformed entries. Never throws.
 *
 * @param {Storage} [storage]
 * @returns {{ mcp: string, ollama: string, anthropic: string }}
 */
export function loadEndpoints(storage) {
    const s = storage ?? (typeof localStorage !== "undefined" ? localStorage : null);
    if (!s) return { ...DEFAULT_ENDPOINTS };
    let raw;
    try { raw = s.getItem(STORAGE_KEY); } catch { return { ...DEFAULT_ENDPOINTS }; }
    if (!raw) return { ...DEFAULT_ENDPOINTS };
    try {
        const parsed = JSON.parse(raw);
        return {
            mcp:       normalizeUrl(parsed.mcp)       ?? DEFAULT_ENDPOINTS.mcp,
            ollama:    normalizeUrl(parsed.ollama)    ?? DEFAULT_ENDPOINTS.ollama,
            anthropic: normalizeUrl(parsed.anthropic) ?? DEFAULT_ENDPOINTS.anthropic,
        };
    } catch {
        return { ...DEFAULT_ENDPOINTS };
    }
}

/**
 * Persist endpoints to localStorage.
 *
 * @param {{ mcp: string, ollama: string, anthropic: string }} endpoints
 * @param {Storage} [storage]
 */
export function saveEndpoints(endpoints, storage) {
    const s = storage ?? (typeof localStorage !== "undefined" ? localStorage : null);
    if (!s) return;
    const out = {
        mcp:       normalizeUrl(endpoints.mcp)       ?? DEFAULT_ENDPOINTS.mcp,
        ollama:    normalizeUrl(endpoints.ollama)    ?? DEFAULT_ENDPOINTS.ollama,
        anthropic: normalizeUrl(endpoints.anthropic) ?? DEFAULT_ENDPOINTS.anthropic,
    };
    try { s.setItem(STORAGE_KEY, JSON.stringify(out)); } catch { /* quota full, ignore */ }
}

/**
 * Normalize a URL: trim whitespace, strip trailing slashes, reject empty.
 * Returns null if the value is not a usable URL-like string.
 *
 * @param {unknown} value
 * @returns {string | null}
 */
export function normalizeUrl(value) {
    if (typeof value !== "string") return null;
    const trimmed = value.trim().replace(/\/+$/, "");
    if (!trimmed) return null;
    if (!/^https?:\/\//i.test(trimmed)) return null;
    return trimmed;
}

/**
 * Fill `{tool_list}`, `{tool_count}`, `{tool_categories}`, `{workflows}`,
 * `{tool_call_format}`, `{tool_schema_hint}`, `{max_words}` in a system prompt
 * template using data from the live MCP tools list and a profile.
 *
 * Mirrors blue_bench_client.runner._build_context + prompts_compose.compose.
 *
 * @param {string} template
 * @param {Array<{ name: string, description?: string, inputSchema?: object }>} tools
 * @param {{ recommended_workflows?: string[] }} profile
 * @returns {string}
 */
export function fillSystemPrompt(template, tools, profile) {
    const context = buildPromptContext(tools, profile);
    return template.replace(/\{([a-zA-Z_][a-zA-Z_0-9]*)\}/g, (full, key) => {
        return Object.prototype.hasOwnProperty.call(context, key) ? context[key] : full;
    });
}

/**
 * Build the placeholder → value map for prompt substitution.
 *
 * @param {Array<{ name: string, description?: string, inputSchema?: object }>} tools
 * @param {{ recommended_workflows?: string[] }} profile
 * @returns {Record<string, string>}
 */
export function buildPromptContext(tools, profile) {
    const list = Array.isArray(tools) ? tools : [];
    const categoryPrefixes = new Set(list.map((t) => String(t?.name ?? "").split("_")[0]).filter(Boolean));
    const lines = list.map((t) => {
        const props = (t?.inputSchema?.properties ?? {});
        const argNames = Object.keys(props).join(", ");
        return `- ${t.name}(${argNames}): ${t.description ?? ""}`;
    });
    return {
        tool_list:       lines.join("\n"),
        tool_count:      String(list.length),
        tool_categories: categoryPrefixes.size ? String(categoryPrefixes.size) : "several",
        workflows:       (profile?.recommended_workflows ?? []).join(", "),
        tool_call_format:
            '```tool_call\\n{"name": "tool_name", "parameters": {"arg": "value"}}\\n```',
        tool_schema_hint:
            "Call tools using the native schema the runtime provides; parameters follow the input_schema field names.",
        max_words: "200",
    };
}

/**
 * Pretty-print a JSON-ish value, truncating if the result exceeds `max` chars.
 *
 * @param {unknown} value
 * @param {number} [max=4000]
 * @returns {string}
 */
export function formatJson(value, max = 4000) {
    let text;
    try { text = JSON.stringify(value, null, 2); } catch { text = String(value); }
    if (text == null) text = String(value);
    if (text.length > max) return text.slice(0, max) + `\n…(truncated, ${text.length - max} chars)`;
    return text;
}

/**
 * Format milliseconds as a short human string: "123 ms" / "2.4 s".
 *
 * @param {number} ms
 * @returns {string}
 */
export function formatElapsed(ms) {
    if (typeof ms !== "number" || !isFinite(ms)) return "—";
    if (ms < 1000) return `${Math.round(ms)} ms`;
    return `${(ms / 1000).toFixed(ms < 10000 ? 2 : 1)} s`;
}

/**
 * Return a compact profile summary line for the UI.
 *
 * @param {{
 *   tool_protocol?: string,
 *   model_id?: string,
 *   context_size?: number,
 *   prompt_style?: string,
 *   recommended_workflows?: string[],
 * }} profile
 */
export function profileSummary(profile) {
    if (!profile) return "";
    const ctx = profile.context_size ? `${Math.round(profile.context_size / 1024)}k ctx` : "";
    const bits = [
        profile.model_id,
        profile.tool_protocol,
        ctx,
        profile.prompt_style,
    ].filter(Boolean);
    return bits.join(" · ");
}
