/**
 * Tool category mapping + suggestion ranking.
 *
 * Security tools (Nmap, Wazuh, Elastic, …) are user-facing groupings of
 * related MCP tools. This is a purely static map — the browser renders
 * expandable checkbox groups from it, and intersects the selected tools
 * with each prompt's `expected_tools` to rank suggestions.
 */

/**
 * @typedef {Object} ToolCategory
 * @property {string} id              stable slug
 * @property {string} label           display name
 * @property {string} description     one-line description
 * @property {Array<string>} tools    MCP tool names owned by this category
 */

/** @type {Array<ToolCategory>} */
export const TOOL_CATEGORIES = [
    {
        id: "elastic",
        label: "Elastic (Suricata / Zeek)",
        description: "Network alerts, flows, aggregations",
        tools: ["search_alerts", "get_connections", "count_by_field"],
    },
    {
        id: "wazuh",
        label: "Wazuh HIDS",
        description: "Host agents and endpoint alerts",
        tools: ["wazuh_list_agents", "get_agent_alerts"],
    },
    {
        id: "openedr",
        label: "OpenEDR",
        description: "Endpoint inventory and detections",
        tools: ["list_endpoints", "get_detections"],
    },
    {
        id: "evidence",
        label: "Evidence (files)",
        description: "File inventory, hashing, strings, metadata",
        tools: ["list_evidence", "file_hash", "file_metadata", "strings_extract"],
    },
    {
        id: "nmap",
        label: "Nmap",
        description: "Active network scanning",
        tools: ["nmap_scan", "nmap_quick_scan"],
    },
    {
        id: "sigma",
        label: "Sigma",
        description: "Detection-rule authoring / validation",
        tools: ["validate_sigma_rule"],
    },
];

/**
 * Map MCP tool name → category id. Derived once from TOOL_CATEGORIES.
 */
export const TOOL_TO_CATEGORY = (() => {
    /** @type {Record<string, string>} */
    const out = {};
    for (const c of TOOL_CATEGORIES) {
        for (const t of c.tools) out[t] = c.id;
    }
    return out;
})();

/**
 * Rank prompts against a set of selected MCP tools.
 *
 * Two-stage ranking so checking any category always yields suggestions:
 *   1. Strict: prompts whose expected_tools ⊆ selectedTools.
 *      Ranked by category-diversity, then by fewer tools, then id.
 *   2. Loose fallback: if strict yields nothing, rank by overlap count
 *      with the selection (any prompt that touches ≥1 selected tool).
 *      Useful for single-category filters where no prompt is purely
 *      scoped to that category (e.g., OpenEDR alone — p2-08 uses
 *      `get_detections` but also needs Elastic + Wazuh tools).
 *
 * When selection is empty, returns prompts ranked by diversity to
 * showcase the tool surface breadth.
 *
 * @param {Array<any>} prompts       entries from prompts.json
 * @param {Set<string>} selectedTools MCP tool names
 * @param {number} [limit=3]
 * @returns {Array<any>}
 */
export function rankPrompts(prompts, selectedTools, limit = 3) {
    if (!prompts?.length) return [];
    const byDiversity = (a, b) => {
        const ac = new Set((a.expected_tools || []).map((t) => TOOL_TO_CATEGORY[t] || t)).size;
        const bc = new Set((b.expected_tools || []).map((t) => TOOL_TO_CATEGORY[t] || t)).size;
        if (ac !== bc) return bc - ac;
        const al = (a.expected_tools || []).length;
        const bl = (b.expected_tools || []).length;
        if (al !== bl) return al - bl;
        return String(a.id).localeCompare(String(b.id));
    };

    if (!selectedTools || selectedTools.size === 0) {
        return [...prompts].sort(byDiversity).slice(0, limit);
    }

    const strict = prompts.filter((p) =>
        (p.expected_tools || []).every((t) => selectedTools.has(t)),
    );
    if (strict.length > 0) return strict.sort(byDiversity).slice(0, limit);

    const loose = prompts
        .map((p) => {
            const overlap = (p.expected_tools || []).filter((t) => selectedTools.has(t)).length;
            return { p, overlap };
        })
        .filter((x) => x.overlap > 0)
        .sort((a, b) => {
            if (a.overlap !== b.overlap) return b.overlap - a.overlap;
            return byDiversity(a.p, b.p);
        });
    return loose.slice(0, limit).map((x) => x.p);
}

/**
 * Union of MCP tool names in the selected categories, filtered to tools
 * the MCP server actually exposes. If no categories are selected or the
 * filter is empty, returns the full live tool-name set (so suggestions
 * still work out of the box).
 *
 * @param {Array<ToolCategory>} categories   TOOL_CATEGORIES
 * @param {Set<string>} selectedCategoryIds
 * @param {Array<any>} liveTools             result of mcp.listTools()
 * @returns {Set<string>}
 */
export function selectedToolNames(categories, selectedCategoryIds, liveTools) {
    const live = new Set((liveTools || []).map((t) => t.name));
    if (!selectedCategoryIds || selectedCategoryIds.size === 0) return live;
    const out = new Set();
    for (const c of categories) {
        if (!selectedCategoryIds.has(c.id)) continue;
        for (const t of c.tools) {
            if (live.has(t)) out.add(t);
        }
    }
    return out;
}
