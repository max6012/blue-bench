/**
 * Integration tests — spawn the real Blue-Bench MCP server over SSE and drive
 * it with the JS client. Opt-in: set BLUE_BENCH_RUN_INTEGRATION=1 to enable,
 * otherwise every test is skipped so CI without docker/python stays green.
 *
 * Run:
 *   BLUE_BENCH_RUN_INTEGRATION=1 node --test tests/mcp_client.integration.test.mjs
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { fileURLToPath } from "node:url";
import path from "node:path";
import net from "node:net";
import fs from "node:fs";
import { createMcpClient } from "../mcp_client.js";

const RUN = process.env.BLUE_BENCH_RUN_INTEGRATION === "1";
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..", "..");

/** Resolve the python executable: env override wins, else search upward for .venv. */
function resolveVenvPython() {
    if (process.env.BLUE_BENCH_PYTHON) return process.env.BLUE_BENCH_PYTHON;
    let dir = REPO_ROOT;
    for (let i = 0; i < 6; i++) {
        const candidate = path.join(dir, ".venv", "bin", "python");
        if (fs.existsSync(candidate)) return candidate;
        const parent = path.dirname(dir);
        if (parent === dir) break;
        dir = parent;
    }
    return null;
}
const VENV_PY = resolveVenvPython();
const PORT = Number(process.env.BLUE_BENCH_SSE_PORT ?? 8766);  // off-default to dodge collisions

/**
 * Spawn the real SSE server, wait for it to listen, hand back a shutdown cb.
 */
async function startServer() {
    if (!VENV_PY) throw new Error("no .venv/bin/python found (set BLUE_BENCH_PYTHON)");
    // Run from REPO_ROOT (the directory that contains blue_bench_mcp) so
    // `-m blue_bench_mcp.server` resolves the package alongside this test —
    // not the one the editable install points at.
    const proc = spawn(VENV_PY, ["-m", "blue_bench_mcp.server", "--transport", "sse", "--port", String(PORT)], {
        cwd: REPO_ROOT,
        stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    proc.stderr.on("data", (chunk) => { stderr += chunk.toString(); });

    // Poll the TCP port until it's open or we time out.
    const deadline = Date.now() + 15_000;
    while (Date.now() < deadline) {
        if (proc.exitCode != null) {
            throw new Error(`server exited early with ${proc.exitCode}\n${stderr}`);
        }
        if (await isOpen("127.0.0.1", PORT)) return { proc, stderr: () => stderr };
        await new Promise((r) => setTimeout(r, 150));
    }
    proc.kill("SIGTERM");
    throw new Error(`server failed to bind to 127.0.0.1:${PORT} within 15s\n${stderr}`);
}

/** @param {string} host @param {number} port */
function isOpen(host, port) {
    return new Promise((resolve) => {
        const sock = net.createConnection({ host, port });
        sock.once("connect", () => { sock.destroy(); resolve(true); });
        sock.once("error", () => resolve(false));
    });
}

async function stopServer(handle) {
    if (!handle) return;
    handle.proc.kill("SIGTERM");
    try { await once(handle.proc, "exit"); } catch {}
}

// Node 25 ships a native EventSource; fall back clearly if missing.
const HAS_EVENT_SOURCE = typeof globalThis.EventSource !== "undefined";

test("live server: initialize + listTools surfaces the Blue-Bench tools", { skip: !RUN || !HAS_EVENT_SOURCE }, async () => {
    const server = await startServer();
    let client;
    try {
        client = await createMcpClient(`http://127.0.0.1:${PORT}`, { requestTimeoutMs: 10_000 });
        const tools = await client.listTools();
        assert.ok(Array.isArray(tools) && tools.length > 0, "expected at least one tool");
        const names = tools.map((t) => t.name);
        // Spot-check a few advertised Blue-Bench tools.
        for (const expected of ["search_alerts", "list_endpoints", "count_by_field"]) {
            assert.ok(names.includes(expected), `missing tool ${expected} — got ${names.join(",")}`);
        }
    } finally {
        client?.close();
        await stopServer(server);
    }
});

test("live server: callTool('list_endpoints', {}) returns a content array", { skip: !RUN || !HAS_EVENT_SOURCE }, async () => {
    const server = await startServer();
    let client;
    try {
        client = await createMcpClient(`http://127.0.0.1:${PORT}`, { requestTimeoutMs: 15_000 });
        const result = await client.callTool("list_endpoints", {});
        assert.ok(result && Array.isArray(result.content), "expected content array in tool result");
    } finally {
        client?.close();
        await stopServer(server);
    }
});
