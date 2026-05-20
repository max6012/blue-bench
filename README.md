# Blue-Bench

**Deployment scaffolding for self-hosted open-weight LLMs in defender workflows.** Blue-Bench wires a local LLM (via Ollama) or a frontier cloud model (via the Anthropic API) into a curated set of Blue Team tools — Elasticsearch queries, Wazuh alerts, OpenEDR detections, Sigma/YARA validation, forensic triage, nmap — through the [Model Context Protocol](https://modelcontextprotocol.io/). Swapping models is a YAML profile change, not a code change.

## Why this exists

Wiring open-weight LLMs into real defender tooling is the hard part. Tool schemas, system-prompt coaching, per-model tool-call protocols, transport choice, model hot-swap, frontier-vs-local trade-offs, browser-vs-CLI clients, network isolation — each is a separate concern, and most stacks couple them. Blue-Bench makes each a **separately editable surface** so the same deployment shape works across very different environments without forking the runtime.

## What you can do with it

- **Drive live investigations from the CLI.** `blue-bench analyst` is a full multi-turn MCP client that streams tool calls in real time and persists sessions across restarts — with local Ollama models or frontier Anthropic models, same command.
- **Swap models without touching the stack.** Every model is a YAML profile. Instructors can hot-swap mid-exercise without touching the tool tier, the system prompt, or the backend containers.
- **Iterate coaching for a specific deployment.** Site overlay (indices, hostnames, IRP conventions) + per-model coaching markdown + git-tracked iteration loop. One commit per lesson. Coaching is opt-in per profile; most models work with the shared role, guidelines, and site overlay alone.
- **Use the same tool surface from any MCP client.** Claude Code, Cline, Continue, the browser frontend, and the analyst CLI all talk to the same MCP server. The server does not know or care which client is on the other end.
- **Validate wiring with a frontier reference run.** A fixed corpus and rubric let you confirm the tool surface, data fixtures, and coaching are sound before attributing results to local-model capability. See [docs/EVAL.md](docs/EVAL.md).

## Quickstart

Requires Python 3.10+, Docker, and a local [Ollama](https://ollama.com/) install.

```bash
# 1. Install
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'

# 2. Bring up the tool tier
docker compose -f docker/compose.tools.yml up -d --build

# 3. Seed Elasticsearch with sample telemetry
python scripts/seed_es.py

# 4. Pull a model
ollama pull gemma4:e4b
# For frontier runs, set ANTHROPIC_API_KEY in .env instead.

# 5. Run the analyst CLI
blue-bench analyst --profile gemma4-e4b

# Or run the evaluation corpus
blue-bench qualify --profile gemma4-e4b --limit 1
```

## Analyst CLI

`blue-bench analyst` is an interactive multi-turn REPL that connects any profile to the live MCP tool surface.

```bash
blue-bench analyst --profile gemma4-e4b              # local model
blue-bench analyst --profile claude-sonnet-4-6       # frontier (requires ANTHROPIC_API_KEY)
blue-bench analyst --profile gemma4-e4b --tools elastic,wazuh   # restrict tool surface
blue-bench analyst --profile gemma4-e4b --resume my-investigation
```

**Session management:** sessions auto-save after every turn to `~/.blue-bench/sessions/`.

| Command | What it does |
| --- | --- |
| `/sessions` | List saved sessions |
| `/save <name>` | Save under a named slot |
| `/load <name>` | Load a saved session |
| `--resume <name>` | Resume at launch |

**Context management:**

| Command | What it does |
| --- | --- |
| `/status` | Context fill bar + per-message breakdown |
| `/compact` | Heuristic compaction — drops old tool result bodies |
| `/compact deep` | LLM-driven summarization of older history |
| `/undo` | Roll back the last turn |

**Other commands:** `/models`, `/tools`, `/gate <cats>`, `/profile <name>`, `/help`.

## Architecture

Three orthogonal design primitives — tools, models, prompts — each a separately editable surface:

- **Tools live in the MCP server.** `blue_bench_mcp/tool_classes/` holds implementations; `blue_bench_mcp/tools/` registers them with the server. Any MCP client sees the same surface.
- **Models are YAML profiles.** `blue_bench_mcp/profiles/<name>.yaml` declares tool-call protocol (`native`, `text-embedded`, or `anthropic-native`), context size, generation params, and which prompt parts to compose. Adding a model is adding a profile.
- **System prompts compose from markdown parts.** `blue_bench_mcp/prompts/{role,site,guidelines,coaching}/*.md` holds the pieces. `prompts_compose.py` assembles them per-request. Nothing is hardcoded. Coaching is per-model and opt-in; role, guidelines, and site overlay are shared.

The MCP server speaks two transports (stdio and SSE) from the same process. Deployment is three independently hostable tiers (tools, LLM, frontend). See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full contract and [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for operational setup.

## Layout

```
blue_bench_mcp/           MCP server — tools, profiles, composable prompts
blue_bench_client/        Reference MCP client + Ollama runner
blue_bench_cli/           Operator CLI: qualify | aggregate | diff | analyst | server
blue_bench_eval/          Validation harness: prompt YAML + rubric + aggregator
blue_bench_frontend/      Browser MCP client (JS, SSE transport)
docker/                   compose.{tools,llm,frontend,all}.yml + Dockerfiles + mock backends
scripts/                  Data seeding + utilities
tests/                    Unit + integration tests (pytest)
docs/                     Architecture, deployment, evaluation methodology
```

Private / gitignored (contributor-local):

```
docs/internal/            Internal planning + narrative
results/                  Run traces + scored JSONs + BLUFs
data/raw/                 Source telemetry (AIT-ADS, Brim, etc.)
data/evidence/            Forensic samples
.plandb.db                Agent task graph state
.claude/                  Assistant session state
```

## Adding a model

1. Write `blue_bench_mcp/profiles/<your-model>.yaml` declaring `model_id`, `tool_protocol`, `context_size`, `generation`, `prompt_parts`.
2. Optionally write `blue_bench_mcp/prompts/coaching/<your-model>.md` for bespoke coaching. Without it, the model gets the shared role, site, and guidelines composition.
3. `blue-bench qualify --profile <your-model>` — run the evaluation.

See **[docs/skills/blue-bench-phase1-eval.md](docs/skills/blue-bench-phase1-eval.md)** for the Phase 1 (no-tool reasoning) eval workflow and scoring guide.  
See **[docs/skills/blue-bench-phase2-eval.md](docs/skills/blue-bench-phase2-eval.md)** for the Phase 2 (live tool call) eval workflow, pre-flight checklist, and failure mode diagnosis.

## Adding a tool

1. Write `blue_bench_mcp/tool_classes/<tool>.py` — one class, N async methods, config from `ServerConfig`, guardrails from `blue_bench_mcp/guardrails.py`.
2. Write `blue_bench_mcp/tools/<tool>.py` — a thin `register(server, cfg)` that wires each method with `@server.tool()`.
3. Restart the server. The tool is discoverable by every MCP client.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full tool contract.

## License

MIT — see [`LICENSE`](LICENSE).

## Contributing

Issues and PRs welcome. Architecture conversations happen in issues; before proposing a large change please open an issue first to avoid duplicate work.
