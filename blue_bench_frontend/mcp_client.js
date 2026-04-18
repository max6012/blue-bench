/**
 * Browser-side MCP client for Blue-Bench.
 *
 * Speaks MCP (Model Context Protocol) JSON-RPC 2.0 over Server-Sent Events:
 *   - GET  <baseUrl>/sse  → EventSource; server pushes an `endpoint` event
 *                           with the URL to POST client messages to, then
 *                           relays JSON-RPC responses/notifications as
 *                           `message` events.
 *   - POST <endpoint>     → client → server JSON-RPC requests/notifications
 *
 * Vanilla ESM. Targets Chrome 120+, Safari 17+, Firefox 120+; also runs in
 * Node 20+ with `--experimental-eventsource` or an injected EventSource.
 *
 * @module mcp_client
 */

import { McpError, deferred, Emitter, buildRequest, buildNotification, newRequestId } from "./json_rpc.js";

export { McpError } from "./json_rpc.js";

const MCP_PROTOCOL_VERSION = "2024-11-05";
const CLIENT_INFO = Object.freeze({ name: "blue-bench-frontend", version: "0.1.0" });
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;

/**
 * @typedef {Object} ToolDefinition
 * @property {string} name
 * @property {string} [description]
 * @property {object} [inputSchema]
 *
 * @typedef {Object} ToolCallResult
 * @property {Array<{ type: string, text?: string, [k: string]: unknown }>} content
 * @property {boolean} [isError]
 *
 * @typedef {Object} McpClientOptions
 * @property {number}      [requestTimeoutMs=30000]
 * @property {typeof EventSource} [EventSource]
 * @property {typeof fetch}       [fetch]
 * @property {{ name: string, version: string }} [clientInfo]
 * @property {string}      [protocolVersion]
 */

/**
 * Browser-side MCP client. Construct via {@link createMcpClient}; do not
 * instantiate directly.
 */
export class McpClient {
    /**
     * @param {string} baseUrl
     * @param {Required<Pick<McpClientOptions, 'requestTimeoutMs' | 'EventSource' | 'fetch' | 'clientInfo' | 'protocolVersion'>>} opts
     */
    constructor(baseUrl, opts) {
        /** @type {string} */
        this.baseUrl = baseUrl.replace(/\/+$/, "");
        this._opts = opts;
        /** @type {EventSource | null} */
        this._es = null;
        /** @type {string | null} */
        this._messageEndpoint = null;
        /** @type {ReturnType<typeof deferred<string>>} */
        this._endpointReady = deferred();
        /** @type {Map<string | number, { resolve: (v: any) => void, reject: (e: Error) => void, timer: ReturnType<typeof setTimeout> | null }>} */
        this._pending = new Map();
        this._emitter = new Emitter();
        this._closed = false;
        /** @type {object | null} */
        this.serverInfo = null;
        /** @type {object | null} */
        this.serverCapabilities = null;
    }

    // ---- public API ------------------------------------------------------

    /** @returns {boolean} */
    get isConnected() {
        return this._es != null && !this._closed && this._messageEndpoint != null;
    }

    /**
     * Register a listener. Events: `progress`, `notification`, `error`, `close`.
     * @param {string} event
     * @param {(payload: any) => void} handler
     */
    on(event, handler) { this._emitter.on(event, handler); }

    /**
     * @param {string} event
     * @param {(payload: any) => void} handler
     */
    off(event, handler) { this._emitter.off(event, handler); }

    /** @returns {Promise<ToolDefinition[]>} */
    async listTools() {
        const res = await this._request("tools/list", {});
        return Array.isArray(res?.tools) ? res.tools : [];
    }

    /**
     * @param {string} name
     * @param {Record<string, unknown>} [args]
     * @returns {Promise<ToolCallResult>}
     */
    async callTool(name, args) {
        const res = await this._request("tools/call", { name, arguments: args ?? {} });
        return /** @type {ToolCallResult} */ (res);
    }

    /** Shut down the SSE connection and reject all pending requests. */
    close() {
        if (this._closed) return;
        this._closed = true;
        if (this._es) { try { this._es.close(); } catch {} this._es = null; }
        const err = new McpError("client closed");
        for (const [, entry] of this._pending) {
            if (entry.timer) clearTimeout(entry.timer);
            entry.reject(err);
        }
        this._pending.clear();
        try { this._endpointReady.reject(err); } catch {}
        this._emitter.emit("close", undefined);
    }

    // ---- lifecycle (internal) -------------------------------------------

    /** @returns {Promise<void>} */
    async _openStream() {
        const ES = this._opts.EventSource;
        const es = new ES(`${this.baseUrl}/sse`);
        this._es = es;

        es.addEventListener("endpoint", (/** @type {MessageEvent} */ ev) => {
            const raw = typeof ev.data === "string" ? ev.data : "";
            try {
                this._messageEndpoint = new URL(raw, this.baseUrl + "/").toString();
                this._endpointReady.resolve(this._messageEndpoint);
            } catch {
                this._emitter.emit("error", new McpError(`invalid endpoint frame: ${raw}`));
            }
        });
        es.addEventListener("message", (/** @type {MessageEvent} */ ev) => this._handleMessageFrame(ev.data));
        es.addEventListener("error", () => {
            const err = new McpError("SSE transport error");
            this._emitter.emit("error", err);
            if (!this._messageEndpoint) { try { this._endpointReady.reject(err); } catch {} }
        });

        await this._endpointReady.promise;
    }

    /** @returns {Promise<void>} */
    async _initialize() {
        const res = await this._request("initialize", {
            protocolVersion: this._opts.protocolVersion,
            capabilities: {},
            clientInfo: this._opts.clientInfo,
        });
        this.serverInfo = res?.serverInfo ?? null;
        this.serverCapabilities = res?.capabilities ?? null;
        await this._notify("notifications/initialized", {});
    }

    /** @param {string} raw */
    _handleMessageFrame(raw) {
        if (typeof raw !== "string" || raw.length === 0) return;
        let msg;
        try { msg = JSON.parse(raw); }
        catch { this._emitter.emit("error", new McpError(`malformed JSON frame: ${raw}`)); return; }
        if (Array.isArray(msg)) { for (const m of msg) this._dispatch(m); }
        else this._dispatch(msg);
    }

    /** @param {any} msg */
    _dispatch(msg) {
        if (!msg || typeof msg !== "object") return;
        if ("id" in msg && (("result" in msg) || ("error" in msg))) {
            const entry = this._pending.get(msg.id);
            if (!entry) return;
            this._pending.delete(msg.id);
            if (entry.timer) clearTimeout(entry.timer);
            if (msg.error) entry.reject(new McpError(msg.error.message ?? "JSON-RPC error", msg.error.code, msg.error.data));
            else entry.resolve(msg.result);
            return;
        }
        if (typeof msg.method === "string" && !("id" in msg)) {
            if (msg.method === "notifications/progress") this._emitter.emit("progress", msg.params ?? {});
            else this._emitter.emit("notification", { method: msg.method, params: msg.params });
        }
    }

    /**
     * @param {string} method
     * @param {Record<string, unknown>} params
     * @returns {Promise<any>}
     */
    async _request(method, params) {
        if (this._closed) throw new McpError("client closed");
        if (!this._messageEndpoint) await this._endpointReady.promise;
        const id = newRequestId();
        const frame = buildRequest(id, method, params);

        const d = deferred();
        const timer = setTimeout(() => {
            if (this._pending.delete(id)) {
                d.reject(new McpError(`request ${method} timed out after ${this._opts.requestTimeoutMs}ms`));
            }
        }, this._opts.requestTimeoutMs);
        this._pending.set(id, { resolve: d.resolve, reject: d.reject, timer });

        try { await this._post(frame); }
        catch (err) { this._pending.delete(id); clearTimeout(timer); throw err; }
        return d.promise;
    }

    /**
     * @param {string} method
     * @param {Record<string, unknown>} params
     * @returns {Promise<void>}
     */
    async _notify(method, params) {
        if (!this._messageEndpoint) await this._endpointReady.promise;
        await this._post(buildNotification(method, params));
    }

    /** @param {object} frame */
    async _post(frame) {
        const endpoint = this._messageEndpoint;
        if (!endpoint) throw new McpError("no message endpoint");
        const res = await this._opts.fetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json", "Accept": "application/json" },
            body: JSON.stringify(frame),
        });
        // MCP's SSE transport returns 202 for client POSTs; the real response
        // arrives over the SSE stream. Any 2xx is success.
        if (!res.ok) {
            let body = "";
            try { body = await res.text(); } catch {}
            throw new McpError(`POST ${endpoint} failed: HTTP ${res.status}${body ? ` — ${body}` : ""}`);
        }
    }
}

/**
 * Create and fully initialize an MCP client over SSE.
 *
 * @param {string} baseUrl              e.g. "http://127.0.0.1:8765"
 * @param {McpClientOptions} [options]
 * @returns {Promise<McpClient>}
 *
 * @example
 * import { createMcpClient } from "./mcp_client.js";
 * const client = await createMcpClient("http://127.0.0.1:8765");
 * const tools  = await client.listTools();
 * const result = await client.callTool("list_endpoints", {});
 * client.close();
 */
export async function createMcpClient(baseUrl, options = {}) {
    const ES = options.EventSource ?? (typeof EventSource !== "undefined" ? EventSource : undefined);
    const f  = options.fetch       ?? (typeof fetch       !== "undefined" ? fetch.bind(globalThis) : undefined);
    if (!ES) throw new McpError("no EventSource implementation available (pass options.EventSource)");
    if (!f)  throw new McpError("no fetch implementation available (pass options.fetch)");

    const opts = {
        requestTimeoutMs: options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS,
        EventSource: ES,
        fetch: f,
        clientInfo: options.clientInfo ?? CLIENT_INFO,
        protocolVersion: options.protocolVersion ?? MCP_PROTOCOL_VERSION,
    };

    const client = new McpClient(baseUrl, opts);
    try {
        await client._openStream();
        await client._initialize();
    } catch (err) {
        client.close();
        throw err;
    }
    return client;
}
