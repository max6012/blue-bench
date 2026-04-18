/**
 * Blue-Bench analyst console — browser UI orchestration.
 *
 * Wires the MCP client + tool-call loop to the DOM. Vanilla ESM.
 *
 * @module app
 */

import { createMcpClient } from "./mcp_client.js";
import { runConversation } from "./loop.js";
import { Emitter } from "./json_rpc.js";
import {
    DEFAULT_ENDPOINTS,
    loadEndpoints,
    saveEndpoints,
    fillSystemPrompt,
    formatJson,
    formatElapsed,
    profileSummary,
} from "./app_utils.js";
import {
    TOOL_CATEGORIES,
    rankPrompts,
    selectedToolNames,
} from "./tool_categories.js";

// ---- DOM handles ---------------------------------------------------------

const $ = (id) => document.getElementById(id);

const ui = {
    cfgMcp:       $("cfg-mcp"),
    cfgOllama:    $("cfg-ollama"),
    cfgAnthropic: $("cfg-anthropic"),
    cfgSave:      $("cfg-save"),
    cfgReset:     $("cfg-reset"),
    cfgToggle:    $("config-toggle"),
    cfgBody:      $("config-body"),
    banner:       $("banner"),
    statusMcp:    $("status-mcp"),
    statusModel:  $("status-model"),
    profileSelect:    $("profile-select"),
    profileMeta:      $("profile-meta"),
    modelOverrideGroup: $("model-override-group"),
    modelOverride:    $("model-override"),
    ollamaModelList:  $("ollama-models"),
    conversation: $("conversation"),
    promptInput:  $("prompt-input"),
    promptForm:   $("prompt-form"),
    runBtn:       $("run-btn"),
    stopBtn:      $("stop-btn"),
    categoryList: $("category-list"),
    toolStatus:   $("tool-status"),
    toolsRefresh: $("tools-refresh"),
    suggestions:     $("suggestions"),
    suggestionsList: $("suggestions-list"),
    progressNote: $("progress-note"),
};

// ---- app state -----------------------------------------------------------

const state = {
    endpoints: loadEndpoints(),
    /** @type {Array<any>} */
    profiles: [],
    /** @type {any | null} */
    selectedProfile: null,
    /** @type {any | null} */
    mcp: null,
    /** @type {Array<any>} */
    tools: [],
    /** @type {Array<any>} */
    prompts: [],
    /** @type {Set<string>} */
    selectedCategories: new Set(),
    /** @type {AbortController | null} */
    abortController: null,
    /** @type {boolean} */
    running: false,
};

// ---- banner + status -----------------------------------------------------

function showBanner(message, { level = "error", onRetry } = {}) {
    ui.banner.hidden = false;
    ui.banner.className = level === "warn" ? "banner banner-warn" : "banner";
    ui.banner.innerHTML = "";
    const span = document.createElement("span");
    span.textContent = message;
    ui.banner.appendChild(span);
    if (onRetry) {
        const actions = document.createElement("span");
        actions.className = "banner-actions";
        const btn = document.createElement("button");
        btn.className = "btn btn-sm";
        btn.textContent = "Retry";
        btn.addEventListener("click", onRetry);
        actions.appendChild(btn);
        ui.banner.appendChild(actions);
    }
}

function clearBanner() { ui.banner.hidden = true; ui.banner.textContent = ""; }

function setChip(el, text, cls) {
    el.textContent = text;
    el.className = `chip ${cls}`;
}

// ---- config panel --------------------------------------------------------

function renderConfig() {
    ui.cfgMcp.value       = state.endpoints.mcp;
    ui.cfgOllama.value    = state.endpoints.ollama;
    ui.cfgAnthropic.value = state.endpoints.anthropic;
}

ui.cfgSave.addEventListener("click", async () => {
    state.endpoints = {
        mcp:       ui.cfgMcp.value.trim(),
        ollama:    ui.cfgOllama.value.trim(),
        anthropic: ui.cfgAnthropic.value.trim(),
    };
    saveEndpoints(state.endpoints);
    await bootMcp();
    await fetchOllamaModels();
});

ui.cfgReset.addEventListener("click", () => {
    state.endpoints = { ...DEFAULT_ENDPOINTS };
    saveEndpoints(state.endpoints);
    renderConfig();
});

ui.cfgToggle.addEventListener("click", () => {
    const expanded = ui.cfgToggle.getAttribute("aria-expanded") === "true";
    ui.cfgToggle.setAttribute("aria-expanded", String(!expanded));
    ui.cfgBody.hidden = expanded;
});

// ---- MCP boot + tool-surface side panel ----------------------------------

async function bootMcp() {
    setChip(ui.statusMcp, "MCP: connecting…", "chip chip-warm");
    ui.toolStatus.hidden = false;
    ui.toolStatus.textContent = "Connecting…";

    if (state.mcp) { try { state.mcp.close(); } catch { /* ignore */ } state.mcp = null; }

    try {
        state.mcp = await createMcpClient(state.endpoints.mcp);
        state.tools = await state.mcp.listTools();
        setChip(ui.statusMcp, `MCP: ${state.tools.length} tools`, "chip chip-ok");
        ui.toolStatus.hidden = true;
        renderCategoryList();
        renderSuggestions();
        clearBanner();
    } catch (err) {
        state.mcp = null;
        state.tools = [];
        setChip(ui.statusMcp, "MCP: offline", "chip chip-bad");
        ui.toolStatus.hidden = false;
        ui.toolStatus.textContent = `Could not connect: ${err?.message ?? err}`;
        renderCategoryList();
        renderSuggestions();
        showBanner(
            `MCP server unreachable at ${state.endpoints.mcp}. Start it with scripts/mcp_server_sse.sh.`,
            { onRetry: bootMcp },
        );
    }
}

function renderCategoryList() {
    ui.categoryList.innerHTML = "";
    const liveToolMap = new Map((state.tools || []).map((t) => [t.name, t]));

    for (const cat of TOOL_CATEGORIES) {
        const row = document.createElement("details");
        row.className = "category-row";
        if (state.selectedCategories.has(cat.id)) row.classList.add("is-selected");

        const summary = document.createElement("summary");
        summary.className = "category-summary";

        const caret = document.createElement("span");
        caret.className = "category-caret";
        caret.textContent = "▸";
        summary.appendChild(caret);

        const cb = document.createElement("input");
        cb.type = "checkbox";
        cb.className = "category-checkbox";
        cb.checked = state.selectedCategories.has(cat.id);
        cb.addEventListener("click", (e) => e.stopPropagation());
        cb.addEventListener("change", () => toggleCategory(cat.id, cb.checked));
        summary.appendChild(cb);

        const label = document.createElement("span");
        label.className = "category-label";
        label.textContent = cat.label;
        summary.appendChild(label);

        const count = document.createElement("span");
        count.className = "category-count";
        count.textContent = String(cat.tools.length);
        summary.appendChild(count);

        row.appendChild(summary);

        const ul = document.createElement("ul");
        ul.className = "category-tools";
        for (const toolName of cat.tools) {
            const tool = liveToolMap.get(toolName);
            const li = document.createElement("li");
            const nm = document.createElement("span");
            nm.textContent = toolName;
            li.appendChild(nm);
            if (tool?.description) {
                const desc = document.createElement("span");
                desc.className = "tool-desc";
                desc.textContent = tool.description;
                li.appendChild(desc);
            }
            ul.appendChild(li);
        }
        row.appendChild(ul);
        ui.categoryList.appendChild(row);
    }
}

function toggleCategory(id, checked) {
    if (checked) state.selectedCategories.add(id);
    else state.selectedCategories.delete(id);
    renderCategoryList();
    renderSuggestions();
}

function renderSuggestions() {
    ui.suggestionsList.innerHTML = "";
    if (!state.prompts.length) { ui.suggestions.hidden = true; return; }
    const selected = selectedToolNames(TOOL_CATEGORIES, state.selectedCategories, state.tools);
    const top = rankPrompts(state.prompts, selected, 3);
    if (!top.length) {
        ui.suggestions.hidden = false;
        const msg = document.createElement("span");
        msg.className = "muted";
        msg.textContent = "No prompts match the selected categories.";
        ui.suggestionsList.appendChild(msg);
        return;
    }
    ui.suggestions.hidden = false;
    for (const p of top) {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "suggestion-chip";
        btn.title = p.question;
        const id = document.createElement("span");
        id.className = "chip-id";
        id.textContent = p.id;
        btn.appendChild(id);
        btn.appendChild(document.createTextNode(p.title));
        btn.addEventListener("click", () => applySuggestion(p));
        ui.suggestionsList.appendChild(btn);
    }
}

function applySuggestion(prompt) {
    ui.promptInput.value = prompt.question;
    ui.promptInput.focus();
    if (!state.running) runPrompt();
}

async function loadPrompts() {
    try {
        const res = await fetch("./prompts.json", { cache: "no-cache" });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const manifest = await res.json();
        state.prompts = Array.isArray(manifest?.prompts) ? manifest.prompts : [];
    } catch {
        state.prompts = [];
    }
    renderSuggestions();
}

ui.toolsRefresh.addEventListener("click", async () => {
    if (!state.mcp) { await bootMcp(); return; }
    try {
        state.tools = await state.mcp.listTools();
        setChip(ui.statusMcp, `MCP: ${state.tools.length} tools`, "chip chip-ok");
        renderCategoryList();
        renderSuggestions();
    } catch (err) {
        ui.toolStatus.hidden = false;
        ui.toolStatus.textContent = `Refresh failed: ${err?.message ?? err}`;
    }
});

// ---- profile picker ------------------------------------------------------

async function loadProfiles() {
    try {
        const res = await fetch("./profiles.json", { cache: "no-cache" });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const manifest = await res.json();
        state.profiles = Array.isArray(manifest?.profiles) ? manifest.profiles : [];
    } catch (err) {
        state.profiles = [];
        showBanner(
            "Could not load profiles.json — run: python scripts/emit_profiles_manifest.py",
            { level: "warn" },
        );
    }

    ui.profileSelect.innerHTML = "";
    if (!state.profiles.length) {
        const opt = document.createElement("option");
        opt.textContent = "(no profiles — generate profiles.json)";
        opt.disabled = true;
        ui.profileSelect.appendChild(opt);
        state.selectedProfile = null;
        ui.profileMeta.textContent = "";
        return;
    }
    for (const p of state.profiles) {
        const opt = document.createElement("option");
        opt.value = p.name;
        opt.textContent = p.name;
        ui.profileSelect.appendChild(opt);
    }
    selectProfile(state.profiles[0].name);
}

function selectProfile(name) {
    const p = state.profiles.find((x) => x.name === name);
    state.selectedProfile = p || null;
    if (!p) { ui.profileMeta.textContent = ""; return; }
    ui.profileSelect.value = p.name;
    ui.profileMeta.textContent = profileSummary(p);
    const usesOllama = p.tool_protocol !== "anthropic-native";
    ui.modelOverrideGroup.hidden = !usesOllama;
    if (!usesOllama) ui.modelOverride.value = "";
    else ui.modelOverride.placeholder = p.model_id;
}

ui.profileSelect.addEventListener("change", (e) => selectProfile(e.target.value));

// ---- ollama model list ---------------------------------------------------

async function fetchOllamaModels() {
    try {
        const res = await fetch(`${state.endpoints.ollama.replace(/\/+$/, "")}/api/tags`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const names = (data?.models ?? []).map((m) => m.name || m.model).filter(Boolean);
        ui.ollamaModelList.innerHTML = "";
        for (const n of names) {
            const opt = document.createElement("option");
            opt.value = n;
            ui.ollamaModelList.appendChild(opt);
        }
    } catch {
        // Soft failure — user can still type an override manually.
        ui.ollamaModelList.innerHTML = "";
    }
}

// ---- conversation rendering ----------------------------------------------

function clearConversation() { ui.conversation.innerHTML = ""; }

function addBubble(role, content, labelOverride) {
    if (!content && role !== "response") return null;
    const div = document.createElement("div");
    div.className = `bubble bubble-${role}`;
    const label = document.createElement("span");
    label.className = "bubble-label";
    label.textContent = labelOverride || role;
    div.appendChild(label);
    const body = document.createElement("div");
    body.textContent = content;
    div.appendChild(body);
    ui.conversation.appendChild(div);
    scrollConversation();
    return div;
}

function addToolCallCard(call) {
    const card = document.createElement("div");
    card.className = "tool-card state-pending";
    card.dataset.toolId = call.id;

    const head = document.createElement("div");
    head.className = "tool-card-head";
    const dot = document.createElement("span"); dot.className = "state-dot"; head.appendChild(dot);
    const name = document.createElement("span"); name.className = "tool-name"; name.textContent = call.name; head.appendChild(name);
    const id = document.createElement("span"); id.className = "tool-id"; id.textContent = `#${String(call.id).slice(0, 8)}`; head.appendChild(id);
    const elapsed = document.createElement("span"); elapsed.className = "elapsed"; elapsed.textContent = "running…"; head.appendChild(elapsed);
    card.appendChild(head);

    const argsDet = document.createElement("details");
    const argsSum = document.createElement("summary"); argsSum.textContent = "arguments"; argsDet.appendChild(argsSum);
    const argsPre = document.createElement("pre"); argsPre.textContent = formatJson(call.args); argsDet.appendChild(argsPre);
    card.appendChild(argsDet);

    const resDet = document.createElement("details");
    const resSum = document.createElement("summary"); resSum.textContent = "result (pending)"; resDet.appendChild(resSum);
    const resPre = document.createElement("pre"); resPre.textContent = "…"; resDet.appendChild(resPre);
    card.appendChild(resDet);

    ui.conversation.appendChild(card);
    scrollConversation();
    return card;
}

function updateToolResult(payload) {
    const card = ui.conversation.querySelector(`.tool-card[data-tool-id="${CSS.escape(String(payload.id))}"]`);
    if (!card) return;
    const isError = payload.result?.isError === true;
    card.classList.remove("state-pending");
    card.classList.add(isError ? "state-error" : "state-ok");

    const elapsed = card.querySelector(".elapsed");
    if (elapsed) elapsed.textContent = formatElapsed(payload.elapsed_ms);

    const detailsEls = card.querySelectorAll("details");
    const resDet = detailsEls[1];
    if (resDet) {
        const sum = resDet.querySelector("summary");
        if (sum) sum.textContent = isError ? "result (error)" : "result";
        const pre = resDet.querySelector("pre");
        if (pre) pre.textContent = formatJson(payload.result);
    }
}

function addErrorCard(message) {
    const div = document.createElement("div");
    div.className = "bubble bubble-error";
    const label = document.createElement("span"); label.className = "bubble-label"; label.textContent = "error"; div.appendChild(label);
    const body = document.createElement("div"); body.textContent = message; div.appendChild(body);
    ui.conversation.appendChild(div);
    scrollConversation();
}

function scrollConversation() {
    requestAnimationFrame(() => { ui.conversation.scrollTop = ui.conversation.scrollHeight; });
}

// ---- run / stop ----------------------------------------------------------

function setRunning(running) {
    state.running = running;
    ui.runBtn.hidden  = running;
    ui.stopBtn.hidden = !running;
    ui.promptInput.disabled = running;
    ui.profileSelect.disabled = running;
    ui.modelOverride.disabled = running;
    if (!running) ui.progressNote.textContent = "";
}

async function runPrompt() {
    const text = ui.promptInput.value.trim();
    if (!text) return;
    if (!state.selectedProfile) { showBanner("Select a profile first."); return; }
    if (!state.mcp) { showBanner("MCP not connected. Fix endpoint and retry."); return; }

    addBubble("user", text);
    ui.promptInput.value = "";

    const profile = buildProfileForRun(state.selectedProfile);
    const events = new Emitter();
    events.on("turn",        (p) => { if (p.content) addBubble("model", p.content, `turn ${p.index}`); });
    events.on("tool_call",   (p) => addToolCallCard(p));
    events.on("tool_result", (p) => updateToolResult(p));
    events.on("response",    (p) => addBubble("response", p.content, "final response"));
    events.on("progress",    (p) => { ui.progressNote.textContent = p.note || ""; });
    events.on("error",       (p) => addErrorCard(p?.error?.message || String(p?.error || p)));

    const systemPrompt = fillSystemPrompt(profile.system_prompt_template, state.tools, profile);
    const abortController = new AbortController();
    state.abortController = abortController;
    setRunning(true);
    setChip(ui.statusModel, `Model: running`, "chip chip-warm");

    try {
        await runConversation({
            profile,
            systemPrompt,
            userPrompt: text,
            mcpClient: state.mcp,
            events,
            signal: abortController.signal,
        });
        setChip(ui.statusModel, "Model: idle", "chip chip-muted");
    } catch (err) {
        if (err?.name === "AbortError") {
            addErrorCard("run aborted by user");
            setChip(ui.statusModel, "Model: aborted", "chip chip-warm");
        } else {
            addErrorCard(err?.message || String(err));
            setChip(ui.statusModel, "Model: error", "chip chip-bad");
        }
    } finally {
        state.abortController = null;
        setRunning(false);
    }
}

/**
 * Build a live profile object for runConversation — the manifest entry plus
 * endpoint overrides and the optional model_id override.
 */
function buildProfileForRun(entry) {
    const p = { ...entry };
    const override = ui.modelOverride.value.trim();
    if (override && entry.tool_protocol !== "anthropic-native") p.model_id = override;
    if (entry.tool_protocol === "anthropic-native") {
        p.anthropic = { proxy_url: state.endpoints.anthropic };
    } else {
        p.ollama = { base_url: state.endpoints.ollama };
    }
    return p;
}

ui.promptForm.addEventListener("submit", (e) => { e.preventDefault(); if (!state.running) runPrompt(); });

ui.stopBtn.addEventListener("click", () => {
    if (state.abortController) state.abortController.abort();
});

ui.promptInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        if (!state.running) runPrompt();
    } else if (e.key === "Escape" && state.running) {
        e.preventDefault();
        if (state.abortController) state.abortController.abort();
    }
});

// ---- boot ----------------------------------------------------------------

async function main() {
    renderConfig();
    setChip(ui.statusMcp, "MCP: idle", "chip chip-muted");
    setChip(ui.statusModel, "Model: idle", "chip chip-muted");
    await loadProfiles();
    await loadPrompts();
    await bootMcp();
    await fetchOllamaModels();
}

main().catch((err) => {
    showBanner(`Startup failed: ${err?.message ?? err}`);
});
