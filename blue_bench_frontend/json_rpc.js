/**
 * JSON-RPC 2.0 primitives shared by mcp_client.js:
 *   - {@link McpError}   Error type carrying `code` and `data`.
 *   - {@link deferred}   Small helper for externally-resolvable promises.
 *   - {@link Emitter}    Minimal event emitter used by the client for
 *                        `progress`, `notification`, `error`, `close`.
 *
 * Kept separate so mcp_client.js can stay under its line budget while still
 * giving consumers a narrow, dependency-free surface.
 *
 * @module json_rpc
 */

/**
 * A JSON-RPC / MCP error raised to the caller.
 */
export class McpError extends Error {
    /**
     * @param {string} message
     * @param {number} [code]
     * @param {unknown} [data]
     */
    constructor(message, code, data) {
        super(message);
        this.name = "McpError";
        /** @type {number | undefined} */
        this.code = code;
        /** @type {unknown} */
        this.data = data;
    }
}

/**
 * A thin-typed deferred: a Promise with externally callable resolve/reject.
 * @template T
 * @returns {{ promise: Promise<T>, resolve: (v: T) => void, reject: (e: Error) => void }}
 */
export function deferred() {
    /** @type {(v: T) => void} */ let resolve;
    /** @type {(e: Error) => void} */ let reject;
    const promise = new Promise((res, rej) => {
        resolve = res;
        reject = rej;
    });
    // @ts-ignore — resolve/reject are assigned synchronously inside the executor.
    return { promise, resolve, reject };
}

/**
 * Very small event emitter — avoids a dependency and keeps the browser bundle
 * tiny. Listeners throwing do NOT break the emitter.
 */
export class Emitter {
    constructor() {
        /** @type {Map<string, Set<(payload: any) => void>>} */
        this._listeners = new Map();
    }
    /**
     * @param {string} event
     * @param {(payload: any) => void} handler
     */
    on(event, handler) {
        let set = this._listeners.get(event);
        if (!set) { set = new Set(); this._listeners.set(event, set); }
        set.add(handler);
    }
    /**
     * @param {string} event
     * @param {(payload: any) => void} handler
     */
    off(event, handler) {
        const set = this._listeners.get(event);
        if (set) set.delete(handler);
    }
    /**
     * @param {string} event
     * @param {any} payload
     */
    emit(event, payload) {
        const set = this._listeners.get(event);
        if (!set) return;
        for (const h of set) {
            try { h(payload); } catch { /* swallow: listener bugs should not crash transport */ }
        }
    }
}

/**
 * Build a JSON-RPC 2.0 request frame.
 * @param {string | number} id
 * @param {string} method
 * @param {Record<string, unknown>} params
 */
export function buildRequest(id, method, params) {
    return { jsonrpc: "2.0", id, method, params };
}

/**
 * Build a JSON-RPC 2.0 notification frame (no id).
 * @param {string} method
 * @param {Record<string, unknown>} params
 */
export function buildNotification(method, params) {
    return { jsonrpc: "2.0", method, params };
}

/**
 * Generate a fresh request id. Uses `crypto.randomUUID` when available.
 * @returns {string}
 */
export function newRequestId() {
    if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
        return crypto.randomUUID();
    }
    return `req-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}
