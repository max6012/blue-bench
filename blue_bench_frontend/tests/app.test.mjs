import { test } from "node:test";
import assert from "node:assert/strict";

import {
    DEFAULT_ENDPOINTS,
    STORAGE_KEY,
    loadEndpoints,
    saveEndpoints,
    normalizeUrl,
    formatJson,
    formatElapsed,
    profileSummary,
    fillSystemPrompt,
    buildPromptContext,
} from "../app_utils.js";

function makeStorage(initial = {}) {
    const store = new Map(Object.entries(initial));
    return {
        getItem: (k) => (store.has(k) ? store.get(k) : null),
        setItem: (k, v) => { store.set(k, String(v)); },
        removeItem: (k) => { store.delete(k); },
        _dump: () => Object.fromEntries(store),
    };
}

test("normalizeUrl trims, strips trailing slash, requires http(s) scheme", () => {
    assert.equal(normalizeUrl("  http://localhost:8765/  "), "http://localhost:8765");
    assert.equal(normalizeUrl("https://example.com/"), "https://example.com");
    assert.equal(normalizeUrl("localhost:8765"), null);
    assert.equal(normalizeUrl(""), null);
    assert.equal(normalizeUrl("   "), null);
    assert.equal(normalizeUrl(null), null);
    assert.equal(normalizeUrl(123), null);
});

test("loadEndpoints returns defaults when storage empty or missing", () => {
    const empty = makeStorage();
    assert.deepEqual(loadEndpoints(empty), { ...DEFAULT_ENDPOINTS });
    assert.deepEqual(loadEndpoints(null), { ...DEFAULT_ENDPOINTS });
});

test("loadEndpoints reads persisted values and normalizes them", () => {
    const storage = makeStorage({
        [STORAGE_KEY]: JSON.stringify({
            mcp: "http://127.0.0.1:8765/",
            ollama: "http://localhost:11434",
            anthropic: "http://localhost:8766/",
        }),
    });
    const out = loadEndpoints(storage);
    assert.equal(out.mcp, "http://127.0.0.1:8765");
    assert.equal(out.ollama, "http://localhost:11434");
    assert.equal(out.anthropic, "http://localhost:8766");
});

test("loadEndpoints falls back to defaults on corrupt JSON", () => {
    const storage = makeStorage({ [STORAGE_KEY]: "{not-json" });
    assert.deepEqual(loadEndpoints(storage), { ...DEFAULT_ENDPOINTS });
});

test("saveEndpoints round-trips through loadEndpoints", () => {
    const storage = makeStorage();
    saveEndpoints({
        mcp: "http://127.0.0.1:9000",
        ollama: "http://localhost:11434/",
        anthropic: "http://localhost:8766",
    }, storage);
    const out = loadEndpoints(storage);
    assert.equal(out.mcp, "http://127.0.0.1:9000");
    assert.equal(out.ollama, "http://localhost:11434");
});

test("formatJson pretty-prints and truncates oversized payloads", () => {
    const small = formatJson({ a: 1 });
    assert.match(small, /"a": 1/);
    const big = formatJson({ data: "x".repeat(10000) }, 100);
    assert.ok(big.length <= 200, `expected truncated output, got ${big.length} chars`);
});

test("formatElapsed humanizes ms into readable units", () => {
    assert.match(formatElapsed(50), /ms/);
    assert.match(formatElapsed(1500), /s/);
});

test("profileSummary renders a one-line summary", () => {
    const s = profileSummary({
        name: "gemma4-e4b",
        model_id: "gemma4:e4b",
        tool_protocol: "native",
        context_size: 8192,
    });
    assert.match(s, /gemma4/);
});

test("buildPromptContext exposes tool-derived placeholders", () => {
    const tools = [
        { name: "search_alerts", description: "Search alerts in Elastic" },
        { name: "list_endpoints", description: "List EDR endpoints" },
    ];
    const ctx = buildPromptContext(tools, { recommended_workflows: ["triage"] });
    assert.ok(typeof ctx.tool_list === "string" && ctx.tool_list.length > 0);
    assert.equal(ctx.tool_count, "2");
});

test("fillSystemPrompt substitutes placeholders and leaves unknowns intact", () => {
    const template = "You have {tool_count} tools. Unknown: {nope}.";
    const out = fillSystemPrompt(template, [
        { name: "a" }, { name: "b" }, { name: "c" },
    ], {});
    assert.match(out, /You have 3 tools\./);
    assert.match(out, /\{nope\}/);
});
