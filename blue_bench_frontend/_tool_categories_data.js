// AUTO-GENERATED from tool_categories.yaml — do not edit by hand.
// Re-run: python scripts/emit_tool_categories.py

/** @type {Array<{id:string,label:string,description:string,tools:string[]}>} */
export const TOOL_CATEGORIES = [
    {
        "id": "elastic",
        "label": "Elastic (Suricata / Zeek)",
        "description": "Network alerts, flows, aggregations",
        "tools": [
            "search_alerts",
            "get_connections",
            "count_by_field"
        ]
    },
    {
        "id": "wazuh",
        "label": "Wazuh HIDS",
        "description": "Host agents and endpoint alerts",
        "tools": [
            "wazuh_list_agents",
            "get_agent_alerts"
        ]
    },
    {
        "id": "openedr",
        "label": "OpenEDR",
        "description": "Endpoint inventory and detections",
        "tools": [
            "list_endpoints",
            "get_detections"
        ]
    },
    {
        "id": "evidence",
        "label": "Evidence (files)",
        "description": "File inventory, hashing, strings, metadata",
        "tools": [
            "list_evidence",
            "file_hash",
            "file_metadata",
            "strings_extract"
        ]
    },
    {
        "id": "nmap",
        "label": "Nmap",
        "description": "Active network scanning",
        "tools": [
            "nmap_scan",
            "nmap_quick_scan"
        ]
    },
    {
        "id": "sigma",
        "label": "Sigma",
        "description": "Detection-rule authoring / validation",
        "tools": [
            "validate_sigma_rule"
        ]
    }
];
