/**
 * Integration test for loop.js — drives a tiny live conversation against the
 * real Blue-Bench MCP server and a local Ollama instance.
 *
 * Opt-in. Requires:
 *   - BLUE_BENCH_RUN_INTEGRATION=1
 *   - a running Ollama on http://127.0.0.1:11434 with a tiny model pulled
 *   - Python venv with blue_bench_mcp installed
 *
 * The model is picked up from BLUE_BENCH_INTEGRATION_MODEL (default: "llama3.2:1b").
 * If any precondition is missing, every test is skipped.
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
import { runConversation } from "../loop.js";

const RUN = process.env.BLUE_BENCH_RUN_INTEGRATION === "1";
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..", "..");
const MODEL = process.env.BLUE_BENCH_INTEGRATION_MODEL || "llama3.2:1b";
const OLLAMA_URL = process.env.BLUE_BENCH_OLLAMA_URL || "http://127.0.0.1:11434";

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
const PORT = Number(process.env.BLUE_BENCH_SSE_PORT ?? 8767);

function isOpen(host, port) {
    return new Promise((resolve) => {
        const sock = net.createConnection({ host, port });
        sock.once("connect", () => { sock.destroy(); resolve(true); });
        sock.once("error", () => resolve(false));
    });
}

async function ollamaReachable() {
    try {
        const res = await fetch(`${OLLAMA_URL}/api/tags`);
        return res.ok;
    } catch { return false; }
}

async function startServer() {
    if (!VENV_PY) throw new Error("no .venv/bin/python found");
    const proc = spawn(VENV_PY, ["-m", "blue_bench_mcp.server", "--transport", "sse", "--port", String(PORT)], {
        cwd: REPO_ROOT, stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    proc.stderr.on("data", (c) => { stderr += c.toString(); });
    const deadline = Date.now() + 15_000;
    while (Date.now() < deadline) {
        if (proc.exitCode != null) throw new Error(`server exited early: ${stderr}`);
        if (await isOpen("127.0.0.1", PORT)) return proc;
        await new Promise((r) => setTimeout(r, 150));
    }
    proc.kill("SIGTERM");
    throw new Error(`server failed to bind within 15s: ${stderr}`);
}

async function stopServer(proc) {
    if (!proc) return;
    proc.kill("SIGTERM");
    try { await once(proc, "exit"); } catch { /* ignore */ }
}

const HAS_ES = typeof globalThis.EventSource !== "undefined";

test("live loop: native branch drives a short conversation end-to-end", { skip: !RUN || !HAS_ES }, async () => {
    if (!(await ollamaReachable())) {
        // eslint-disable-next-line no-console
        console.warn(`Ollama not reachable at ${OLLAMA_URL}; skipping.`);
        return;
    }
    const server = await startServer();
    let client;
    try {
        client = await createMcpClient(`http://127.0.0.1:${PORT}`, { requestTimeoutMs: 30_000 });
        const profile = {
            model_id: MODEL,
            tool_protocol: "native",
            generation: { temperature: 0, top_p: 1 },
            context_size: 4096,
            ollama: { base_url: OLLAMA_URL },
        };
        const result = await runConversation({
            profile,
            systemPrompt: "You are a security analyst. Use the tools available. Keep answers short.",
            userPrompt: "List the endpoints and tell me how many there are.",
            mcpClient: client,
            maxTurns: 4,
        });
        // Weak but meaningful: we got SOME answer back.
        assert.ok(result.finalResponse.length > 0 || result.trace.turns.length > 0);
    } finally {
        client?.close();
        await stopServer(server);
    }
});
