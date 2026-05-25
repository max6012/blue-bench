"""PCAP downloader for MTA catalogue entries.

Targeted fetch of catalogue entries to ``data/raw/mta/<incident_id>/`` (which
is gitignored repo-wide via the top-level ``data/raw/`` entry). Unzips with
the documented MTA password (``infected``); fails loud if the password is
rejected. Verifies SHA256 if the catalogue carries an expected hash; warns
otherwise (we deliberately do not gate on missing hashes — many catalogue
entries are added before a known-good archive hash is captured).

License posture: this downloader does not re-host MTA content. Files land
under ``data/raw/`` and are NEVER committed.
"""

from __future__ import annotations

import hashlib
import logging
import re
import subprocess
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from blue_bench_generators.cybercrime_foil.catalogue import (
    CATALOGUE,
    MTA_ZIP_PASSWORD,
    CatalogueEntry,
    get,
)

log = logging.getLogger(__name__)


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RAW_DIR = REPO_ROOT / "data" / "raw" / "mta"


class DownloadError(RuntimeError):
    """Raised when a fetch / unzip / hash-verification step fails."""


def _writeup_to_zip_url(writeup_url: str) -> str:
    """Map ``/<YYYY>/<MM>/<DD>/index.html`` to the conventional zip filename.

    MTA names PCAP zips ``<YYYY-MM-DD>-<slug>.pcap.zip`` and hosts them
    alongside the index page. The slug is NOT recoverable from the index URL
    alone — we'd need to scrape the index page to learn it. For v1, callers
    that need the actual zip URL must either (a) supply it explicitly, or
    (b) accept that the writeup URL is for human reference and the zip URL
    requires HTML scraping.

    This helper returns the directory portion of the URL so callers can
    list/fetch zips relative to it.
    """
    parsed = urlparse(writeup_url)
    # Strip trailing ``index.html`` if present.
    path = re.sub(r"/index\.html?$", "/", parsed.path)
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def _sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _http_get(url: str, dest: Path) -> None:
    log.info("downloading %s -> %s", url, dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    # Use stdlib urllib so we don't add a new dep just for downloads.
    # MTA serves static HTTPS; no auth needed.
    with urllib.request.urlopen(url) as resp:  # noqa: S310 — MTA is the documented source.
        with dest.open("wb") as f:
            while True:
                chunk = resp.read(1 << 16)
                if not chunk:
                    break
                f.write(chunk)


def _unzip(archive: Path, dest_dir: Path, password: str = MTA_ZIP_PASSWORD) -> list[Path]:
    """Unzip a password-protected archive using the ``unzip`` CLI.

    We shell out to ``unzip`` because Python's ``zipfile`` only handles the
    older ZipCrypto algorithm and many modern MTA archives use AES-encrypted
    zips that stdlib cannot decrypt. ``unzip`` (info-zip) covers both.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["unzip", "-o", "-P", password, str(archive), "-d", str(dest_dir)]
    log.info("unzip %s -> %s", archive.name, dest_dir)
    try:
        result = subprocess.run(  # noqa: S603 — args constructed from validated paths.
            cmd,
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise DownloadError(
            "the `unzip` CLI is not installed; required to extract MTA archives"
        ) from exc
    if result.returncode != 0:
        raise DownloadError(
            f"unzip failed (rc={result.returncode}) on {archive.name}:\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return [p for p in dest_dir.rglob("*") if p.is_file()]


def download(
    entry_or_id: CatalogueEntry | str,
    zip_url: str,
    *,
    raw_dir: Path = DEFAULT_RAW_DIR,
    skip_if_present: bool = True,
) -> Path:
    """Fetch one catalogue entry's PCAP archive into ``raw_dir/<incident_id>/``.

    Args:
        entry_or_id: catalogue entry or its incident_id.
        zip_url: explicit URL of the ``.pcap.zip`` archive. Callers obtain
            this by scraping the writeup page (out of scope for v1) or by
            supplying it from a side channel. Not derivable from the writeup
            URL alone — see ``_writeup_to_zip_url`` for the structural reason.
        raw_dir: parent directory under which ``<incident_id>/`` is created.
            Defaults to ``data/raw/mta/`` relative to repo root.
        skip_if_present: if True and the archive already exists, skip the
            network fetch and return the cached path.

    Returns:
        Path to the downloaded archive (still zipped). Caller may pass to
        ``unzip_archive`` to extract.

    Raises:
        DownloadError on network, hash, or filesystem failure.
    """
    entry = entry_or_id if isinstance(entry_or_id, CatalogueEntry) else get(entry_or_id)
    incident_dir = raw_dir / entry.incident_id
    archive_name = Path(urlparse(zip_url).path).name or f"{entry.incident_id}.zip"
    archive = incident_dir / archive_name

    if archive.exists() and skip_if_present:
        log.info("archive already present; skipping fetch: %s", archive)
    else:
        try:
            _http_get(zip_url, archive)
        except Exception as exc:  # noqa: BLE001 — re-raise with context
            raise DownloadError(f"fetch failed for {zip_url}: {exc}") from exc

    if entry.archive_sha256:
        actual = _sha256_of(archive)
        if actual != entry.archive_sha256:
            raise DownloadError(
                f"sha256 mismatch for {archive.name}: "
                f"expected {entry.archive_sha256}, got {actual}"
            )
        log.info("sha256 verified for %s", archive.name)
    else:
        log.warning(
            "no expected sha256 in catalogue for %s; downloaded archive is unverified",
            entry.incident_id,
        )

    return archive


def unzip_archive(
    entry_or_id: CatalogueEntry | str,
    archive: Path,
    *,
    raw_dir: Path = DEFAULT_RAW_DIR,
) -> list[Path]:
    """Unzip ``archive`` into ``raw_dir/<incident_id>/extracted/``."""
    entry = entry_or_id if isinstance(entry_or_id, CatalogueEntry) else get(entry_or_id)
    dest = raw_dir / entry.incident_id / "extracted"
    return _unzip(archive, dest)


def list_catalogue() -> None:
    """Log a one-line summary of every catalogue entry."""
    for e in CATALOGUE:
        log.info(
            "%s  [%s]  %s  -- %s",
            e.incident_id,
            e.attribution_fidelity,
            e.date,
            e.family,
        )
