"""Session storage for the analyst CLI.

A *session* is the full state of an analyst's investigation: which profile
they're running, what tool gate is active, and the live conversation
history (the messages that the model sees on the next turn). Saving a
session and reloading it via ``--resume`` should produce a session whose
behavior is indistinguishable from one that never exited.

Layout::

    ~/.blue-bench/sessions/
        <id>.json             # one self-contained file per session
        <id>.json.tmp         # atomic-write staging (auto-cleaned on success)

A session id is `<UTC-timestamp>-<profile_name>` by default
(e.g. ``20260503-114502-gemma4-e4b``); the analyst can override with
``--session <name>`` or in-REPL ``/save <name>``.

The on-disk schema is versioned (``schema_version``) so future schema
changes can migrate forward at load time without breaking existing
sessions. We bump on any breaking change to ``messages`` shape.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

SCHEMA_VERSION = "blue-bench-analyst/1"
DEFAULT_SESSIONS_DIR = Path.home() / ".blue-bench" / "sessions"

_ID_SAFE_RE = re.compile(r"^[a-zA-Z0-9._\-]+$")


@dataclass
class SessionState:
    """Self-contained session record. Roundtrips through JSON.

    Fields named to match the keys consumers will type interactively:
    ``id``, ``profile_name``, ``model_id``, ``tool_protocol``, ``tool_gate``,
    ``messages``, ``turns``. The ``turns`` list is a render-friendly event
    log (matching :class:`TranscriptRecorder` shape) — it is *not*
    re-played to the model on resume; ``messages`` is the live context.
    """

    id: str
    profile_name: str
    model_id: str
    tool_protocol: str
    tool_gate: Optional[list[str]]
    """List of *category ids* (e.g. ``["elastic","wazuh"]``) — None = unrestricted.
    We persist category ids rather than tool-name sets so the gate stays
    meaningful if the underlying category-to-tool mapping evolves."""
    messages: list[dict[str, Any]]
    turns: list[dict[str, Any]] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)
    name: Optional[str] = None
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SessionState":
        version = data.get("schema_version")
        if version != SCHEMA_VERSION:
            raise ValueError(
                f"unsupported session schema_version {version!r} "
                f"(this build expects {SCHEMA_VERSION!r})"
            )
        # Drop any unknown fields so future-added fields don't error here;
        # asdict-style dataclasses don't accept unknown kwargs.
        known = {
            "id", "profile_name", "model_id", "tool_protocol",
            "tool_gate", "messages", "turns",
            "started_at", "last_updated", "name", "schema_version",
        }
        return cls(**{k: v for k, v in data.items() if k in known})


# ── path helpers ─────────────────────────────────────────────────────────────

def default_sessions_dir(env: dict[str, str] | None = None) -> Path:
    """Resolve where sessions live. ``BLUE_BENCH_SESSIONS_DIR`` overrides."""
    env = env if env is not None else os.environ  # type: ignore[assignment]
    custom = env.get("BLUE_BENCH_SESSIONS_DIR")
    if custom:
        return Path(custom).expanduser()
    return DEFAULT_SESSIONS_DIR


def ensure_sessions_dir(sessions_dir: Path | None = None) -> Path:
    """Create the sessions dir if missing; return its path."""
    d = sessions_dir or default_sessions_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d


def session_path(session_id: str, sessions_dir: Path | None = None) -> Path:
    """Return the canonical JSON path for ``session_id``."""
    if not _ID_SAFE_RE.match(session_id):
        raise ValueError(
            f"session id {session_id!r} contains characters outside "
            f"[A-Za-z0-9._-]; pick a friendlier name"
        )
    return (sessions_dir or default_sessions_dir()) / f"{session_id}.json"


def auto_session_id(profile_name: str, *, when: datetime | None = None) -> str:
    """``YYYYMMDD-HHMMSS-<profile>`` (UTC) for unguided runs."""
    ts = (when or datetime.now(timezone.utc)).strftime("%Y%m%d-%H%M%S")
    safe_profile = re.sub(r"[^a-zA-Z0-9._\-]", "-", profile_name)
    return f"{ts}-{safe_profile}"


# ── load / save ──────────────────────────────────────────────────────────────

def save_session(state: SessionState, sessions_dir: Path | None = None) -> Path:
    """Write ``state`` to ``<sessions_dir>/<id>.json`` atomically.

    Atomic = stage to ``<id>.json.tmp``, fsync, rename. A reader cannot
    observe a partially-written file even if the process is killed during
    the write.
    """
    state.last_updated = time.time()
    target = session_path(state.id, sessions_dir)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(".json.tmp")
    payload = json.dumps(state.to_dict(), indent=2, default=str)
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(payload)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, target)
    return target


def load_session(session_id: str, sessions_dir: Path | None = None) -> SessionState:
    """Load a session by id. Raises ``FileNotFoundError`` if missing."""
    path = session_path(session_id, sessions_dir)
    if not path.exists():
        raise FileNotFoundError(
            f"no session named {session_id!r} in "
            f"{sessions_dir or default_sessions_dir()}"
        )
    return SessionState.from_dict(json.loads(path.read_text(encoding="utf-8")))


def session_exists(session_id: str, sessions_dir: Path | None = None) -> bool:
    """True iff a session with this id has a readable file on disk."""
    try:
        return session_path(session_id, sessions_dir).exists()
    except ValueError:
        return False


def list_sessions(sessions_dir: Path | None = None) -> list[SessionState]:
    """Enumerate sessions sorted by ``last_updated`` descending."""
    d = sessions_dir or default_sessions_dir()
    if not d.exists():
        return []
    out: list[SessionState] = []
    for p in d.glob("*.json"):
        if p.name.endswith(".tmp"):
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            out.append(SessionState.from_dict(data))
        except (json.JSONDecodeError, ValueError, KeyError):
            # Bad file — skip rather than crash. The analyst's other
            # sessions matter more than one corrupt one.
            continue
    out.sort(key=lambda s: s.last_updated, reverse=True)
    return out
