/**
 * Unit tests for mcp_client.js.
 *
 * These tests mock EventSource + fetch so they run offline. They verify:
 *   - the SSE handshake (endpoint frame → message endpoint captured)
 *   - the `initialize` request/response round-trip
 *   - `listTools` / `callTool` send well-formed JSON-RPC and resolve on response
 *   - JSON-RPC errors reject the caller with an McpError
 *   - progress notifications surface on the `progress` event
 *   - `close()` cleans up pending requests and EventSource
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createMcpClient, McpClient, McpError } from "../mcp_client.js";

// ---- fakes ---------------------------------------------------------------

/**
 * Minimal EventSource stub that exposes hooks for the test to push frames.
 */
class FakeEventSource {
    /** @type {FakeEventSource[]} */
    static instances = [];
    /** @param {string} url */
    constructor(url) {
        this.url = url;
        /** @type {Record<string, Array<(ev: any) => void>>} */
        this._listeners = {};
        this.closed = false;
        FakeEventSource.instances.push(this);
    }
    /** @param {string} type  @param {(ev: any) => void} handler */
    addEventListener(type, handler) {
        (this._listeners[type] ||= []).push(handler);
    }
    close() { this.closed = true; }

    // test helpers
    /** @param {string} type  @param {string} data */
    _emit(type, data) {
        for (const h of (this._listeners[type] ?? [])) h({ data });
    }
    _emitError() {
        for (const h of (this._listeners["error"] ?? [])) h({});
    }
}

/**
 * A fake fetch that records POST bodies and calls the on-request handler so
 * the test can reply via SSE.
 */
function makeFakeFetch(onRequest) {
    /** @type {Array<{ url: string, body: any }>} */
    const calls = [];
    async function fakeFetch(url, init) {
        const body = JSON.parse(init.body);
        calls.push({ url, body });
        // Schedule the server-side reply asynchronously.
        queueMicrotask(() => onRequest(body, url));
        return new Response("", { status: 202 });
    }
    fakeFetch.calls = calls;
    return fakeFetch;
}

/**
 * Build a fresh { client-promise, es, fetchCalls, pushFrame } harness.
 * `respond(body)` is what the fake server does with each client POST.
 */
async function buildHarness({ respond, protocolVersion = "2024-11-05" } = {}) {
    FakeEventSource.instances.length = 0;
    /** @type {FakeEventSource | null} */
    let activeEs = null;

    const fetch = makeFakeFetch((body, url) => {
        // Default responder: give a generic empty result to any request.
        const reply = respond ? respond(body, url) : { jsonrpc: "2.0", id: body.id, result: {} };
        if (reply == null) return;  // responder decided to withhold
        if (!activeEs) return;
        activeEs._emit("message", JSON.stringify(reply));
    });

    const clientP = createMcpClient("http://127.0.0.1:8765", {
        EventSource: FakeEventSource,
        fetch,
        protocolVersion,
        requestTimeoutMs: 500,
    });

    // Wait for the EventSource to be constructed, then send the `endpoint`
    // frame so initialize can POST.
    await new Promise((r) => queueMicrotask(r));
    activeEs = FakeEventSource.instances[0];
    assert.ok(activeEs, "EventSource should have been constructed");
    activeEs._emit("endpoint", "/messages/?session_id=abc123");

    return { clientP, getEs: () => activeEs, fetch };
}

// ---- tests ---------------------------------------------------------------

test("createMcpClient performs initialize handshake and captures serverInfo", async () => {
    const { clientP } = await buildHarness({
        respond: (body) => {
            if (body.method === "initialize") {
                return {
                    jsonrpc: "2.0",
                    id: body.id,
                    result: {
                        protocolVersion: "2024-11-05",
                        capabilities: { tools: { listChanged: false } },
                        serverInfo: { name: "test-server", version: "0.0.1" },
                    },
                };
            }
            return null;  // swallow the `notifications/initialized` — it's a notification anyway
        },
    });
    const client = await clientP;
    assert.ok(client instanceof McpClient);
    assert.equal(client.isConnected, true);
    assert.deepEqual(client.serverInfo, { name: "test-server", version: "0.0.1" });
    assert.equal(client.serverCapabilities?.tools?.listChanged, false);
    client.close();
});

test("listTools returns the tool list from tools/list", async () => {
    const tools = [
        { name: "search_alerts", description: "…", inputSchema: { type: "object" } },
        { name: "list_endpoints", description: "…", inputSchema: { type: "object" } },
    ];
    const { clientP } = await buildHarness({
        respond: (body) => {
            if (body.method === "initialize") {
                return { jsonrpc: "2.0", id: body.id, result: { protocolVersion: "2024-11-05", capabilities: {}, serverInfo: { name: "x", version: "0" } } };
            }
            if (body.method === "tools/list") {
                return { jsonrpc: "2.0", id: body.id, result: { tools } };
            }
            return null;
        },
    });
    const client = await clientP;
    const listed = await client.listTools();
    assert.deepEqual(listed, tools);
    client.close();
});

test("callTool sends name+arguments and resolves to the server's result", async () => {
    const { clientP, fetch } = await buildHarness({
        respond: (body) => {
            if (body.method === "initialize") return { jsonrpc: "2.0", id: body.id, result: { protocolVersion: "2024-11-05", capabilities: {}, serverInfo: { name: "x", version: "0" } } };
            if (body.method === "tools/call") {
                assert.equal(body.params.name, "list_endpoints");
                assert.deepEqual(body.params.arguments, { limit: 5 });
                return { jsonrpc: "2.0", id: body.id, result: { content: [{ type: "text", text: "[]" }], isError: false } };
            }
            return null;
        },
    });
    const client = await clientP;
    const result = await client.callTool("list_endpoints", { limit: 5 });
    assert.equal(result.isError, false);
    assert.equal(result.content[0].text, "[]");
    // Sanity-check that POSTs actually went to the endpoint the server advertised.
    for (const call of fetch.calls) {
        assert.match(call.url, /\/messages\/\?session_id=abc123$/);
    }
    client.close();
});

test("JSON-RPC errors reject the caller with McpError carrying code + data", async () => {
    const { clientP } = await buildHarness({
        respond: (body) => {
            if (body.method === "initialize") return { jsonrpc: "2.0", id: body.id, result: { protocolVersion: "2024-11-05", capabilities: {}, serverInfo: { name: "x", version: "0" } } };
            if (body.method === "tools/call") {
                return { jsonrpc: "2.0", id: body.id, error: { code: -32602, message: "Invalid params", data: { field: "limit" } } };
            }
            return null;
        },
    });
    const client = await clientP;
    await assert.rejects(
        () => client.callTool("list_endpoints", {}),
        (err) => err instanceof McpError && err.code === -32602 && /Invalid params/.test(err.message),
    );
    client.close();
});

test("progress notifications are surfaced on the progress event", async () => {
    const { clientP, getEs } = await buildHarness({
        respond: (body) => {
            if (body.method === "initialize") return { jsonrpc: "2.0", id: body.id, result: { protocolVersion: "2024-11-05", capabilities: {}, serverInfo: { name: "x", version: "0" } } };
            if (body.method === "tools/call") return { jsonrpc: "2.0", id: body.id, result: { content: [], isError: false } };
            return null;
        },
    });
    const client = await clientP;
    const seen = [];
    client.on("progress", (p) => seen.push(p));

    // Server pushes a progress notification mid-flight.
    getEs()._emit("message", JSON.stringify({
        jsonrpc: "2.0",
        method: "notifications/progress",
        params: { progressToken: "abc", progress: 0.5, total: 1 },
    }));
    await client.callTool("list_endpoints", {});
    assert.equal(seen.length, 1);
    assert.equal(seen[0].progress, 0.5);
    client.close();
});

test("close() rejects pending requests and shuts the EventSource", async () => {
    // Responder never replies to tools/call, so the request stays pending.
    const { clientP, getEs } = await buildHarness({
        respond: (body) => {
            if (body.method === "initialize") return { jsonrpc: "2.0", id: body.id, result: { protocolVersion: "2024-11-05", capabilities: {}, serverInfo: { name: "x", version: "0" } } };
            return null;
        },
    });
    const client = await clientP;
    const p = client.callTool("slow_tool", {});
    client.close();
    await assert.rejects(p, (err) => err instanceof McpError && /client closed/.test(err.message));
    assert.equal(getEs().closed, true);
});

test("malformed JSON frames surface as error events without crashing", async () => {
    const { clientP, getEs } = await buildHarness({
        respond: (body) => {
            if (body.method === "initialize") return { jsonrpc: "2.0", id: body.id, result: { protocolVersion: "2024-11-05", capabilities: {}, serverInfo: { name: "x", version: "0" } } };
            return null;
        },
    });
    const client = await clientP;
    const errors = [];
    client.on("error", (e) => errors.push(e));
    getEs()._emit("message", "{not json");
    assert.equal(errors.length, 1);
    assert.ok(errors[0] instanceof McpError);
    client.close();
});

test("createMcpClient rejects if SSE fails before endpoint frame arrives", async () => {
    FakeEventSource.instances.length = 0;
    const fetch = async () => new Response("", { status: 202 });
    const p = createMcpClient("http://127.0.0.1:8765", {
        EventSource: FakeEventSource,
        fetch,
        requestTimeoutMs: 200,
    });
    // Wait a microtask for the constructor to register listeners.
    await new Promise((r) => queueMicrotask(r));
    FakeEventSource.instances[0]._emitError();
    await assert.rejects(p, (err) => err instanceof McpError);
});
