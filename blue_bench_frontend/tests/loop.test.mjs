/**
 * Unit tests for loop.js — the browser-side tool-call loop.
 *
 * Mocks `fetch` and the MCP client so tests run offline.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
    runConversation,
    parseTextEmbeddedToolCalls,
    toOllamaTools,
    toAnthropicTools,
} from "../loop.js";
import { Emitter } from "../json_rpc.js";

// ---- helpers -------------------------------------------------------------

/**
 * Build a mock MCP client that returns the given tool list from `listTools()`
 * and dispatches `callTool` to a handler.
 */
function mockMcp(tools, handler) {
    /** @type {Array<{ name: string, args: any }>} */
    const calls = [];
    return {
        listTools: async () => tools,
        callTool: async (name, args) => {
            calls.push({ name, args });
            const out = handler ? await handler(name, args) : { content: [{ type: "text", text: "ok" }] };
            if (typeof out === "string") return { content: [{ type: "text", text: out }] };
            return out;
        },
        _calls: calls,
    };
}

/**
 * Encode an array of objects as an Ollama NDJSON stream body.
 */
function ndjsonResponse(chunks) {
    const text = chunks.map((c) => JSON.stringify(c)).join("\n") + "\n";
    const stream = new ReadableStream({
        start(ctrl) {
            ctrl.enqueue(new TextEncoder().encode(text));
            ctrl.close();
        },
    });
    return new Response(stream, { status: 200, headers: { "Content-Type": "application/x-ndjson" } });
}

/**
 * Encode a sequence of SSE event frames (array of {event, data}) as a stream.
 */
function sseResponse(frames) {
    const text = frames.map((f) => `event: ${f.event}\ndata: ${JSON.stringify(f.data)}\n\n`).join("");
    const stream = new ReadableStream({
        start(ctrl) {
            ctrl.enqueue(new TextEncoder().encode(text));
            ctrl.close();
        },
    });
    return new Response(stream, { status: 200, headers: { "Content-Type": "text/event-stream" } });
}

/**
 * Collect events into a flat ordered log `[eventName, payload]`.
 */
function recordEvents(emitter) {
    const log = [];
    for (const name of ["turn", "tool_call", "tool_result", "response", "error", "progress"]) {
        emitter.on(name, (p) => log.push([name, p]));
    }
    return log;
}

const BASE_PROFILE = Object.freeze({
    model_id: "gemma4:e4b",
    tool_protocol: "native",
    generation: { temperature: 0.2, top_p: 1 },
    context_size: 8192,
    ollama: { base_url: "http://127.0.0.1:11434" },
});

// ---- schema helpers ------------------------------------------------------

test("toOllamaTools wraps MCP definitions in the function schema", () => {
    const tools = [{ name: "list_endpoints", description: "list", inputSchema: { type: "object", properties: {} } }];
    const out = toOllamaTools(tools);
    assert.equal(out[0].type, "function");
    assert.equal(out[0].function.name, "list_endpoints");
    assert.equal(out[0].function.parameters.type, "object");
});

test("toAnthropicTools uses the flat input_schema shape", () => {
    const tools = [{ name: "list_endpoints", description: "list", inputSchema: { type: "object" } }];
    const out = toAnthropicTools(tools);
    assert.deepEqual(out[0], { name: "list_endpoints", description: "list", input_schema: { type: "object" } });
});

// ---- text-embedded parser ------------------------------------------------

test("parseTextEmbeddedToolCalls finds fenced tool_call blocks", () => {
    const text = "Plan:\n```tool_call\n{\"name\": \"list_endpoints\", \"parameters\": {\"limit\": 5}}\n```\n";
    const calls = parseTextEmbeddedToolCalls(text);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].name, "list_endpoints");
    assert.deepEqual(calls[0].args, { limit: 5 });
});

test("parseTextEmbeddedToolCalls handles legacy <tool>/<args> tags", () => {
    const text = "<tool>search_alerts</tool><args>{\"severity\": \"high\"}</args>";
    const calls = parseTextEmbeddedToolCalls(text);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].name, "search_alerts");
    assert.deepEqual(calls[0].args, { severity: "high" });
});

test("parseTextEmbeddedToolCalls falls back to bare JSON", () => {
    const text = 'I will call {"name": "list_endpoints", "parameters": {"limit": 3}}';
    const calls = parseTextEmbeddedToolCalls(text);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].name, "list_endpoints");
    assert.deepEqual(calls[0].args, { limit: 3 });
});

test("parseTextEmbeddedToolCalls tolerates trailing commas", () => {
    const text = "```tool_call\n{\"name\": \"list_endpoints\", \"parameters\": {\"limit\": 5,},}\n```";
    const calls = parseTextEmbeddedToolCalls(text);
    assert.equal(calls.length, 1);
    assert.deepEqual(calls[0].args, { limit: 5 });
});

// ---- native branch -------------------------------------------------------

test("native: model emits a tool_call, result fed back, final response", async () => {
    const mcp = mockMcp(
        [{ name: "list_endpoints", description: "list", inputSchema: { type: "object" } }],
        async () => ({ content: [{ type: "text", text: '[{"id":1}]' }] }),
    );

    /** @type {Array<{url: string, body: any}>} */
    const fetchCalls = [];
    let turn = 0;
    async function fakeFetch(url, init) {
        fetchCalls.push({ url, body: JSON.parse(init.body) });
        turn += 1;
        if (turn === 1) {
            // First turn: model requests a tool.
            return ndjsonResponse([
                { message: { content: "", tool_calls: [{ id: "t1", function: { name: "list_endpoints", arguments: { limit: 5 } } }] }, done: false },
                { done: true },
            ]);
        }
        // Second turn: final answer.
        return ndjsonResponse([
            { message: { content: "Found 1 endpoint." }, done: false },
            { done: true },
        ]);
    }

    const events = new Emitter();
    const log = recordEvents(events);
    const result = await runConversation({
        profile: BASE_PROFILE,
        systemPrompt: "system",
        userPrompt: "list endpoints",
        mcpClient: mcp,
        events,
        fetch: fakeFetch,
    });

    assert.equal(result.finalResponse, "Found 1 endpoint.");
    assert.equal(fetchCalls.length, 2);
    assert.equal(fetchCalls[0].body.model, "gemma4:e4b");
    assert.ok(Array.isArray(fetchCalls[0].body.tools));
    // Second turn's messages should include a tool response.
    const secondMessages = fetchCalls[1].body.messages;
    assert.ok(secondMessages.some((m) => m.role === "tool" && m.content.includes("[{\"id\":1}]")));

    // Event order: turn (assistant with tool) → tool_call → tool_result → turn (final) → response.
    const names = log.map((e) => e[0]);
    assert.deepEqual(names, ["turn", "tool_call", "tool_result", "turn", "response"]);
    assert.equal(log[1][1].name, "list_endpoints");
    assert.equal(log[2][1].name, "list_endpoints");
});

test("native: empty final turn triggers force-synthesis retry", async () => {
    const mcp = mockMcp([{ name: "list_endpoints", description: "", inputSchema: {} }], async () => "ok");

    let turn = 0;
    /** @type {Array<any>} */
    const bodies = [];
    async function fakeFetch(_url, init) {
        bodies.push(JSON.parse(init.body));
        turn += 1;
        if (turn === 1) {
            return ndjsonResponse([
                { message: { content: "", tool_calls: [{ function: { name: "list_endpoints", arguments: {} } }] } },
                { done: true },
            ]);
        }
        if (turn === 2) {
            // Second turn: empty content, no tool calls — triggers retry.
            return ndjsonResponse([{ message: { content: "" } }, { done: true }]);
        }
        // Force-synthesis retry: returns real content.
        return ndjsonResponse([{ message: { content: "Final synthesized answer." } }, { done: true }]);
    }

    const events = new Emitter();
    const log = recordEvents(events);
    const result = await runConversation({
        profile: BASE_PROFILE,
        systemPrompt: "sys",
        userPrompt: "q",
        mcpClient: mcp,
        events,
        fetch: fakeFetch,
    });
    assert.equal(result.finalResponse, "Final synthesized answer.");
    // The third fetch should carry the FORCE_SYNTHESIS_PROMPT as last user message.
    const lastMessages = bodies[2].messages;
    const lastUser = lastMessages[lastMessages.length - 1];
    assert.equal(lastUser.role, "user");
    assert.match(lastUser.content, /analyst-facing/);
    // Progress event should have fired for the retry.
    assert.ok(log.some((e) => e[0] === "progress" && /force-synthesis/.test(e[1].note)));
});

test("native: empty retry salvages last non-empty assistant content", async () => {
    const mcp = mockMcp([{ name: "x", description: "", inputSchema: {} }], async () => "ok");
    let turn = 0;
    async function fakeFetch(_url, init) {
        turn += 1;
        if (turn === 1) {
            return ndjsonResponse([
                { message: { content: "Preamble: checking.", tool_calls: [{ function: { name: "x", arguments: {} } }] } },
                { done: true },
            ]);
        }
        // Both the second turn and the retry return empty.
        return ndjsonResponse([{ message: { content: "" } }, { done: true }]);
    }
    const result = await runConversation({
        profile: BASE_PROFILE, systemPrompt: "", userPrompt: "", mcpClient: mcp, fetch: fakeFetch,
    });
    assert.equal(result.finalResponse, "Preamble: checking.");
});

test("native: max_turns stops a runaway loop", async () => {
    const mcp = mockMcp([{ name: "x", description: "", inputSchema: {} }], async () => "ok");
    async function fakeFetch() {
        // Always tool-call; never terminates.
        return ndjsonResponse([
            { message: { content: "calling", tool_calls: [{ function: { name: "x", arguments: {} } }] } },
            { done: true },
        ]);
    }
    const result = await runConversation({
        profile: BASE_PROFILE, systemPrompt: "", userPrompt: "", mcpClient: mcp,
        fetch: fakeFetch, maxTurns: 3,
    });
    assert.equal(result.finalResponse, "calling");
    assert.match(result.trace.error || "", /max_turns \(3\)/);
});

test("native: 500 from Ollama surfaces as error", async () => {
    const mcp = mockMcp([], async () => "");
    async function fakeFetch() {
        return new Response("boom", { status: 500 });
    }
    await assert.rejects(
        () => runConversation({
            profile: BASE_PROFILE, systemPrompt: "", userPrompt: "q", mcpClient: mcp, fetch: fakeFetch,
        }),
        /Ollama HTTP 500/,
    );
});

test("native: abort signal cancels mid-turn", async () => {
    const mcp = mockMcp([{ name: "x", description: "", inputSchema: {} }], async () => "ok");
    const controller = new AbortController();
    async function fakeFetch(_url, init) {
        // Abort before any response arrives.
        controller.abort();
        if (init.signal?.aborted) throw new DOMException("aborted", "AbortError");
        return ndjsonResponse([{ done: true }]);
    }
    await assert.rejects(
        () => runConversation({
            profile: BASE_PROFILE, systemPrompt: "", userPrompt: "q", mcpClient: mcp,
            fetch: fakeFetch, signal: controller.signal,
        }),
        (err) => err.name === "AbortError",
    );
});

// ---- text-embedded branch ------------------------------------------------

test("text-embedded: fenced tool call parsed, result fed back as user message", async () => {
    const mcp = mockMcp(
        [{ name: "list_endpoints", description: "", inputSchema: {} }],
        async () => ({ content: [{ type: "text", text: "[1,2]" }] }),
    );
    let turn = 0;
    /** @type {Array<any>} */
    const bodies = [];
    async function fakeFetch(_url, init) {
        bodies.push(JSON.parse(init.body));
        turn += 1;
        if (turn === 1) {
            return ndjsonResponse([
                { message: { content: "```tool_call\n{\"name\": \"list_endpoints\", \"parameters\": {}}\n```" } },
                { done: true },
            ]);
        }
        return ndjsonResponse([{ message: { content: "Done." } }, { done: true }]);
    }

    const profile = { ...BASE_PROFILE, tool_protocol: "text-embedded" };
    const events = new Emitter();
    const log = recordEvents(events);
    const result = await runConversation({
        profile, systemPrompt: "s", userPrompt: "q", mcpClient: mcp, fetch: fakeFetch, events,
    });
    assert.equal(result.finalResponse, "Done.");
    // No tools schema on text-embedded.
    assert.equal(bodies[0].tools, undefined);
    // Second turn has a synthetic <tool_result> user message.
    const second = bodies[1].messages;
    const lastUser = second[second.length - 1];
    assert.equal(lastUser.role, "user");
    assert.match(lastUser.content, /<tool_result name="list_endpoints">/);
    assert.ok(log.some((e) => e[0] === "tool_call"));
    assert.ok(log.some((e) => e[0] === "tool_result"));
});

test("text-embedded: no tool call → content becomes final answer", async () => {
    const mcp = mockMcp([], async () => "");
    async function fakeFetch() {
        return ndjsonResponse([{ message: { content: "Immediate answer." } }, { done: true }]);
    }
    const profile = { ...BASE_PROFILE, tool_protocol: "text-embedded" };
    const result = await runConversation({
        profile, systemPrompt: "s", userPrompt: "q", mcpClient: mcp, fetch: fakeFetch,
    });
    assert.equal(result.finalResponse, "Immediate answer.");
});

// ---- anthropic-native branch ---------------------------------------------

test("anthropic-native: SSE stream with tool_use → tool_result → final text", async () => {
    const mcp = mockMcp(
        [{ name: "list_endpoints", description: "list", inputSchema: { type: "object" } }],
        async () => ({ content: [{ type: "text", text: '[{"id":"e1"}]' }] }),
    );
    let turn = 0;
    /** @type {Array<any>} */
    const bodies = [];
    async function fakeFetch(url, init) {
        assert.match(url, /\/v1\/messages$/);
        bodies.push(JSON.parse(init.body));
        turn += 1;
        if (turn === 1) {
            return sseResponse([
                { event: "message_start", data: { type: "message_start", message: { id: "m1" } } },
                { event: "content_block_start", data: { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: "tu_1", name: "list_endpoints", input: {} } } },
                { event: "content_block_delta", data: { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: "{" } } },
                { event: "content_block_delta", data: { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: "\"limit\":3}" } } },
                { event: "content_block_stop", data: { type: "content_block_stop", index: 0 } },
                { event: "message_delta", data: { type: "message_delta", delta: { stop_reason: "tool_use" } } },
                { event: "message_stop", data: { type: "message_stop" } },
            ]);
        }
        return sseResponse([
            { event: "content_block_start", data: { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } } },
            { event: "content_block_delta", data: { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "There is 1 endpoint." } } },
            { event: "content_block_stop", data: { type: "content_block_stop", index: 0 } },
            { event: "message_delta", data: { type: "message_delta", delta: { stop_reason: "end_turn" } } },
        ]);
    }

    const profile = {
        model_id: "claude-sonnet-4-6",
        tool_protocol: "anthropic-native",
        generation: { temperature: 0.2, max_tokens: 1024 },
        context_size: 200000,
        anthropic: { proxy_url: "http://127.0.0.1:9000" },
    };
    const events = new Emitter();
    const log = recordEvents(events);
    const result = await runConversation({
        profile, systemPrompt: "sys", userPrompt: "how many?", mcpClient: mcp, fetch: fakeFetch, events,
    });

    assert.equal(result.finalResponse, "There is 1 endpoint.");
    // First call passed tools and a cached system block.
    assert.equal(bodies[0].system[0].cache_control.type, "ephemeral");
    assert.ok(Array.isArray(bodies[0].tools));
    // Tool args were assembled from input_json_delta.
    const toolCall = log.find((e) => e[0] === "tool_call");
    assert.equal(toolCall[1].name, "list_endpoints");
    assert.deepEqual(toolCall[1].args, { limit: 3 });
    // Second request carried tool_result block.
    const second = bodies[1].messages;
    const lastUser = second[second.length - 1];
    assert.equal(lastUser.role, "user");
    assert.equal(lastUser.content[0].type, "tool_result");
    assert.equal(lastUser.content[0].tool_use_id, "tu_1");
});

test("anthropic-native: missing proxy_url throws a clear error", async () => {
    const mcp = mockMcp([], async () => "");
    const profile = {
        model_id: "claude-sonnet-4-6",
        tool_protocol: "anthropic-native",
        generation: { temperature: 0.2 },
        context_size: 200000,
    };
    await assert.rejects(
        () => runConversation({ profile, systemPrompt: "", userPrompt: "", mcpClient: mcp, fetch: async () => new Response() }),
        /proxy_url is required/,
    );
});

// ---- misc ----------------------------------------------------------------

test("unknown tool_protocol rejects immediately", async () => {
    const mcp = mockMcp([], async () => "");
    await assert.rejects(
        () => runConversation({
            profile: { ...BASE_PROFILE, tool_protocol: "bogus" },
            systemPrompt: "", userPrompt: "", mcpClient: mcp, fetch: async () => new Response(),
        }),
        /unknown tool_protocol: bogus/,
    );
});

test("malformed tool response: non-JSON NDJSON lines are skipped", async () => {
    const mcp = mockMcp([], async () => "");
    async function fakeFetch() {
        const text = "not-json\n" + JSON.stringify({ message: { content: "ok" } }) + "\n" + JSON.stringify({ done: true }) + "\n";
        const stream = new ReadableStream({
            start(ctrl) { ctrl.enqueue(new TextEncoder().encode(text)); ctrl.close(); },
        });
        return new Response(stream, { status: 200 });
    }
    const result = await runConversation({
        profile: BASE_PROFILE, systemPrompt: "", userPrompt: "", mcpClient: mcp, fetch: fakeFetch,
    });
    assert.equal(result.finalResponse, "ok");
});
