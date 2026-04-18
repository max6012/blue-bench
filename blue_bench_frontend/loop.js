/**
 * Browser-side tool-call loop for Blue-Bench.
 *
 * Drives: prompt → model → tool_calls → MCP dispatch → tool_results → model,
 * repeating until the model produces a final textual answer. Mirrors the
 * Python runner in `blue_bench_client/runner.py` exactly, with the same three
 * protocol branches keyed on `profile.tool_protocol`:
 *
 *   - "native"            Ollama `/api/chat` with a `tools` schema; structured
 *                         `tool_calls` in the response.
 *   - "text-embedded"     Ollama `/api/chat`, no tool schema; the model emits
 *                         ```tool_call ... ``` fenced JSON.
 *   - "anthropic-native"  Anthropic Messages API via a local proxy, with the
 *                         native `tool_use` / `tool_result` block protocol.
 *
 * Parity targets with `runner.py`:
 *   - Identical turn ordering.
 *   - Same fenced + legacy + bare-JSON tool-call parsers for text-embedded.
 *   - Same `_force_final_synthesis_native` retry for the G4 empty-final quirk.
 *   - On max-turns, salvage the last non-empty assistant content.
 *
 * Zero npm deps. ES2022. Chrome 120+ / Safari 17+ / Firefox 120+ / Node 20+.
 *
 * @module loop
 */

import { Emitter } from "./json_rpc.js";
import {
    toOllamaTools,
    toAnthropicTools,
    flattenToolResult,
    parseTextEmbeddedToolCalls,
    readOllamaStream,
    readAnthropicResponse,
} from "./tool_adapter.js";

export { toOllamaTools, toAnthropicTools, parseTextEmbeddedToolCalls, Emitter };

const FORCE_SYNTHESIS_PROMPT =
    "Based on your tool results so far, produce the final analyst-facing " +
    "answer now. Include the specific findings from each tool call — " +
    "IPs, signatures, counts, hashes, filenames — not a plan or a " +
    "summary of what you'll do next. The answer itself.";

// ---- shared helpers ------------------------------------------------------

/** Strip undefined values so request bodies are tight. */
function pruneUndefined(o) {
    for (const k of Object.keys(o)) if (o[k] === undefined) delete o[k];
    return o;
}

/** @param {object} profile */
function ollamaOptions(profile) {
    const g = profile.generation ?? {};
    return pruneUndefined({
        temperature: g.temperature,
        top_p: g.top_p,
        num_ctx: profile.context_size,
        top_k: g.top_k,
    });
}

async function ollamaChat(profile, messages, tools, io) {
    const f = io.fetch ?? fetch.bind(globalThis);
    const base = profile.ollama?.base_url || "http://127.0.0.1:11434";
    const body = pruneUndefined({
        model: profile.model_id,
        messages,
        stream: true,
        options: ollamaOptions(profile),
        tools: tools && tools.length ? tools : undefined,
    });
    const res = await f(`${base.replace(/\/+$/, "")}/api/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal: io.signal,
    });
    return readOllamaStream(res, io.signal);
}

async function dispatchTool(mcp, name, args) {
    const t0 = performance.now();
    const raw = await mcp.callTool(name, args);
    const elapsed_ms = Math.round(performance.now() - t0);
    return { text: flattenToolResult(raw), elapsed_ms, raw };
}

function salvageLastAssistant(trace, skipFromEnd = 0) {
    for (let i = trace.turns.length - 1 - skipFromEnd; i >= 0; i--) {
        const t = trace.turns[i];
        if (t.role === "assistant" && t.content) return t.content;
    }
    return "";
}

function checkAbort(signal) {
    if (signal?.aborted) throw new DOMException("aborted", "AbortError");
}

// ---- native (Ollama tool_calls) ------------------------------------------

async function runNative(ctx) {
    const { profile, systemPrompt, userPrompt, mcpClient, maxTurns, signal, events, trace, fetchImpl } = ctx;
    const messages = [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt },
    ];
    const toolSpecs = toOllamaTools(await mcpClient.listTools());

    for (let i = 0; i < maxTurns; i++) {
        checkAbort(signal);
        const t0 = performance.now();
        const { message } = await ollamaChat(profile, messages, toolSpecs, { fetch: fetchImpl, signal });
        const dur = Math.round(performance.now() - t0);
        const content = message.content || "";
        const rawToolCalls = Array.isArray(message.tool_calls) ? message.tool_calls : [];

        const calls = rawToolCalls.map((tc) => ({
            id: tc.id ?? `call_${trace.turns_used}_${Math.random().toString(36).slice(2, 8)}`,
            name: tc.function?.name ?? tc.name,
            args: tc.function?.arguments ?? tc.arguments ?? {},
        }));

        trace.turns.push({ role: "assistant", content, tool_calls: calls, duration_ms: dur });
        trace.turns_used += 1;
        events.emit("turn", { index: i, role: "assistant", content });
        messages.push({ role: "assistant", content, tool_calls: rawToolCalls });

        if (calls.length === 0) {
            if (content) { trace.final_answer = content; events.emit("response", { content }); return; }
            await forceFinalSynthesisNative(ctx, messages, toolSpecs);
            return;
        }

        for (const tc of calls) {
            checkAbort(signal);
            events.emit("tool_call", { id: tc.id, name: tc.name, args: tc.args });
            const { text, elapsed_ms, raw } = await dispatchTool(mcpClient, tc.name, tc.args);
            trace.turns.push({ role: "tool", content: text, tool_name: tc.name, duration_ms: elapsed_ms });
            events.emit("tool_result", { id: tc.id, name: tc.name, result: raw, elapsed_ms });
            messages.push({ role: "tool", content: text });
        }
    }

    trace.final_answer = salvageLastAssistant(trace);
    trace.error = `max_turns (${maxTurns}) exhausted without final answer`;
    if (trace.final_answer) events.emit("response", { content: trace.final_answer });
}

/** One-shot forcing retry when the native branch ends with empty content. */
async function forceFinalSynthesisNative(ctx, messages, toolSpecs) {
    const { profile, events, trace, signal, fetchImpl } = ctx;
    messages.push({ role: "user", content: FORCE_SYNTHESIS_PROMPT });
    events.emit("progress", { note: "force-synthesis retry" });
    const t0 = performance.now();
    const { message } = await ollamaChat(profile, messages, toolSpecs, { fetch: fetchImpl, signal });
    const dur = Math.round(performance.now() - t0);
    const retry = message.content || "";
    trace.turns.push({ role: "assistant", content: retry, tool_calls: [], duration_ms: dur });
    trace.turns_used += 1;
    events.emit("turn", { index: trace.turns_used - 1, role: "assistant", content: retry });
    if (retry) { trace.final_answer = retry; events.emit("response", { content: retry }); return; }
    // Retry also empty — skip last two turns (empty final + empty retry) when salvaging.
    const salvaged = salvageLastAssistant(trace, 2);
    if (salvaged) { trace.final_answer = salvaged; events.emit("response", { content: salvaged }); }
}

// ---- text-embedded -------------------------------------------------------

async function runTextEmbedded(ctx) {
    const { profile, systemPrompt, userPrompt, mcpClient, maxTurns, signal, events, trace, fetchImpl } = ctx;
    const messages = [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt },
    ];
    // Tools are described in the system prompt (composed externally); do not pass schema.
    await mcpClient.listTools();

    for (let i = 0; i < maxTurns; i++) {
        checkAbort(signal);
        const t0 = performance.now();
        const { message } = await ollamaChat(profile, messages, undefined, { fetch: fetchImpl, signal });
        const dur = Math.round(performance.now() - t0);
        const content = message.content || "";

        const parsed = parseTextEmbeddedToolCalls(content);
        const calls = parsed.map((c, idx) => ({
            id: `call_${trace.turns_used}_${idx}`,
            name: c.name,
            args: c.args,
        }));

        trace.turns.push({ role: "assistant", content, tool_calls: calls, duration_ms: dur });
        trace.turns_used += 1;
        events.emit("turn", { index: i, role: "assistant", content });
        messages.push({ role: "assistant", content });

        if (calls.length === 0) {
            trace.final_answer = content;
            events.emit("response", { content });
            return;
        }

        for (const tc of calls) {
            checkAbort(signal);
            events.emit("tool_call", { id: tc.id, name: tc.name, args: tc.args });
            const { text, elapsed_ms, raw } = await dispatchTool(mcpClient, tc.name, tc.args);
            trace.turns.push({ role: "tool", content: text, tool_name: tc.name, duration_ms: elapsed_ms });
            events.emit("tool_result", { id: tc.id, name: tc.name, result: raw, elapsed_ms });
            messages.push({
                role: "user",
                content: `<tool_result name="${tc.name}">\n${text}\n</tool_result>`,
            });
        }
    }

    trace.error = `max_turns (${maxTurns}) exhausted without final answer`;
}

// ---- anthropic-native ----------------------------------------------------

async function runAnthropic(ctx) {
    const { profile, systemPrompt, userPrompt, mcpClient, maxTurns, signal, events, trace, fetchImpl } = ctx;
    const f = fetchImpl ?? fetch.bind(globalThis);
    const proxyUrl = profile.anthropic?.proxy_url;
    if (!proxyUrl) throw new Error("profile.anthropic.proxy_url is required for anthropic-native");
    const anthropicVersion = profile.anthropic?.anthropic_version || "2023-06-01";

    const tools = toAnthropicTools(await mcpClient.listTools());
    const systemBlocks = [{ type: "text", text: systemPrompt, cache_control: { type: "ephemeral" } }];
    const messages = [{ role: "user", content: userPrompt }];
    const maxTokens = profile.generation?.max_tokens ?? 4096;

    for (let i = 0; i < maxTurns; i++) {
        checkAbort(signal);
        const body = pruneUndefined({
            model: profile.model_id,
            max_tokens: maxTokens,
            system: systemBlocks,
            messages,
            tools,
            temperature: profile.generation?.temperature,
        });
        const t0 = performance.now();
        const res = await f(`${proxyUrl.replace(/\/+$/, "")}/v1/messages`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "anthropic-version": anthropicVersion,
            },
            body: JSON.stringify(body),
            signal,
        });
        const resp = await readAnthropicResponse(res);
        const dur = Math.round(performance.now() - t0);

        const textParts = [];
        /** @type {Array<{ id: string, name: string, input: object }>} */
        const toolUses = [];
        for (const block of resp.content || []) {
            if (!block) continue;
            if (block.type === "text") textParts.push(block.text || "");
            else if (block.type === "tool_use") toolUses.push({ id: block.id, name: block.name, input: block.input || {} });
        }
        const contentText = textParts.join("\n");
        const calls = toolUses.map((tu) => ({ id: tu.id, name: tu.name, args: tu.input }));

        trace.turns.push({ role: "assistant", content: contentText, tool_calls: calls, duration_ms: dur });
        trace.turns_used += 1;
        events.emit("turn", { index: i, role: "assistant", content: contentText });
        messages.push({ role: "assistant", content: resp.content });

        if (resp.stop_reason !== "tool_use") {
            if (contentText) { trace.final_answer = contentText; events.emit("response", { content: contentText }); return; }
            const salvaged = salvageLastAssistant(trace, 1);
            if (salvaged) { trace.final_answer = salvaged; events.emit("response", { content: salvaged }); }
            return;
        }

        /** @type {Array<object>} */
        const toolResultBlocks = [];
        for (const tu of toolUses) {
            checkAbort(signal);
            events.emit("tool_call", { id: tu.id, name: tu.name, args: tu.input });
            const { text, elapsed_ms, raw } = await dispatchTool(mcpClient, tu.name, tu.input);
            trace.turns.push({ role: "tool", content: text, tool_name: tu.name, duration_ms: elapsed_ms });
            events.emit("tool_result", { id: tu.id, name: tu.name, result: raw, elapsed_ms });
            toolResultBlocks.push({ type: "tool_result", tool_use_id: tu.id, content: text });
        }
        messages.push({ role: "user", content: toolResultBlocks });
    }

    trace.final_answer = salvageLastAssistant(trace);
    trace.error = `max_turns (${maxTurns}) exhausted without final answer`;
    if (trace.final_answer) events.emit("response", { content: trace.final_answer });
}

// ---- public API ----------------------------------------------------------

/**
 * @typedef {Object} Profile
 * @property {string} model_id
 * @property {"native"|"text-embedded"|"anthropic-native"} tool_protocol
 * @property {object} generation
 * @property {number} [context_size]
 * @property {{ base_url?: string }} [ollama]
 * @property {{ proxy_url?: string, anthropic_version?: string }} [anthropic]
 *
 * @typedef {Object} RunResult
 * @property {string} finalResponse
 * @property {{ turns: Array<object>, turns_used: number, final_answer?: string, error?: string }} trace
 * @property {Emitter} events
 */

/**
 * Drive a full model ↔ tool conversation.
 *
 * Events emitted (in order): `turn` → `tool_call`+ → `tool_result`+ → ... →
 * `response` (or `error`). A UI can mirror this stream directly.
 *
 * @param {{
 *   profile: Profile,
 *   systemPrompt: string,
 *   userPrompt: string,
 *   mcpClient: { listTools: () => Promise<any[]>, callTool: (name: string, args: object) => Promise<any> },
 *   maxTurns?: number,
 *   signal?: AbortSignal,
 *   events?: Emitter,
 *   fetch?: typeof fetch,
 * }} args
 * @returns {Promise<RunResult>}
 */
export async function runConversation(args) {
    const {
        profile,
        systemPrompt,
        userPrompt,
        mcpClient,
        maxTurns = 10,
        signal,
        events = new Emitter(),
        fetch: fetchImpl,
    } = args;

    /** @type {{ turns: Array<any>, turns_used: number, final_answer?: string, error?: string }} */
    const trace = { turns: [], turns_used: 0 };

    const ctx = { profile, systemPrompt, userPrompt, mcpClient, maxTurns, signal, events, trace, fetchImpl };

    try {
        if (profile.tool_protocol === "native") await runNative(ctx);
        else if (profile.tool_protocol === "anthropic-native") await runAnthropic(ctx);
        else if (profile.tool_protocol === "text-embedded") await runTextEmbedded(ctx);
        else throw new Error(`unknown tool_protocol: ${profile.tool_protocol}`);
    } catch (err) {
        trace.error = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
        events.emit("error", { error: err });
        throw err;
    }

    return { finalResponse: trace.final_answer ?? "", trace, events };
}
