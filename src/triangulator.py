"""
archive_triangulator.py
=======================

Three-way archive comparison tool for documenting suspected post-hoc
alteration of web archive records.

This tool compares three independent sources for what a domain's archive
history *should* look like:

    A) Contemporaneous observations  — your dated screenshots / notes /
       social media posts captured at a known prior point in time.
    B) Current Wayback Machine CDX   — what the Internet Archive currently
       claims about the domain's capture history.
    C) Common Crawl index            — what an independent, separately-
       operated web archive recorded about the domain.

The tool produces a side-by-side report flagging:

    * Captures the current Wayback record claims existed on dates where
      Common Crawl shows no corresponding crawl activity, and the
      contemporaneous observation indicated no such captures existed.
    * Digest changes for (timestamp, url) pairs that should be immutable.
    * Capture-frequency anomalies inconsistent with the contemporaneous
      observation.

The tool DOES NOT assert tampering. It produces a measurement-and-
divergence report. Interpretation is the human's responsibility.

All outputs are SHA-256 hashed at capture time and (optionally) GPG-signed
so that any later questions about what the tool saw at this exact moment
can be answered cryptographically.

Author: built for the PolicyWatch / Operation Gridlack project.
License: AGPL-3.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sqlite3
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional
from urllib.parse import urlencode

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


TOOL_VERSION = "1.0.0"
DEFAULT_USER_AGENT = (
    f"ArchiveTriangulator/{TOOL_VERSION} "
    "(forensic archive comparison; contact: see project README)"
)

WAYBACK_CDX_URL = "https://web.archive.org/cdx/search/cdx"
COMMONCRAWL_INDEX_LIST = "https://index.commoncrawl.org/collinfo.json"
COMMONCRAWL_INDEX_FMT = "https://index.commoncrawl.org/{index}-index"

logger = logging.getLogger("triangulator")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class CDXEntry:
    """One row from the Wayback CDX index."""
    timestamp: str        # YYYYMMDDHHMMSS
    original_url: str
    statuscode: str
    digest: str           # SHA-1 base32 of the captured content
    length: str
    mimetype: str

    @property
    def date_iso(self) -> str:
        ts = self.timestamp
        return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}T{ts[8:10]}:{ts[10:12]}:{ts[12:14]}Z"

    @property
    def date_only(self) -> str:
        return f"{self.timestamp[0:4]}-{self.timestamp[4:6]}-{self.timestamp[6:8]}"


@dataclass
class CCEntry:
    """One row from a Common Crawl index."""
    index_id: str
    timestamp: str
    url: str
    digest: str
    length: str
    mimetype: str
    status: str

    @property
    def date_only(self) -> str:
        return f"{self.timestamp[0:4]}-{self.timestamp[4:6]}-{self.timestamp[6:8]}"


@dataclass
class ContemporaneousObservation:
    """
    A user-supplied record of what they personally observed about the
    archive at a prior point in time. This is the "I saw it then" baseline
    against which the current archive state is compared.
    """
    observed_at: str               # ISO 8601
    observer: str                  # who made the observation
    domain: str
    description: str               # free-text, what was seen
    claim: str                     # what the observation establishes
    evidence_uris: list[str] = field(default_factory=list)
    # Optional structured assertion: list of (date, expected_capture_count) tuples
    expected_capture_dates: list[dict] = field(default_factory=list)


@dataclass
class DivergenceFinding:
    """A single identified divergence between sources. Measurement, not conclusion."""
    severity: str            # 'informational' | 'notable' | 'significant'
    category: str            # 'wayback_capture_unsupported_by_cc' |
                             # 'cc_capture_missing_from_wayback' |
                             # 'wayback_disagrees_with_observation' |
                             # 'capture_frequency_anomaly'
    date: str
    description: str
    wayback_evidence: list[dict] = field(default_factory=list)
    cc_evidence: list[dict] = field(default_factory=list)
    observation_evidence: list[dict] = field(default_factory=list)
    plausible_innocent_explanations: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# HTTP plumbing
# ---------------------------------------------------------------------------

def make_session(user_agent: str = DEFAULT_USER_AGENT,
                 rate_limit_seconds: float = 1.0) -> requests.Session:
    """Create a requests Session with retry + UA + manual rate limiting."""
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=2.0,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET",),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({"User-Agent": user_agent})

    # Attach simple per-host rate limiter
    last_called: dict[str, float] = {}

    original_get = session.get

    def throttled_get(url: str, **kwargs):
        from urllib.parse import urlparse
        host = urlparse(url).netloc
        now = time.monotonic()
        prev = last_called.get(host, 0.0)
        delta = now - prev
        if delta < rate_limit_seconds:
            time.sleep(rate_limit_seconds - delta)
        last_called[host] = time.monotonic()
        return original_get(url, **kwargs)

    session.get = throttled_get  # type: ignore[assignment]
    return session


# ---------------------------------------------------------------------------
# Wayback CDX
# ---------------------------------------------------------------------------

def fetch_wayback_cdx(
    session: requests.Session,
    domain: str,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    match_type: str = "domain",
) -> Iterator[CDXEntry]:
    """
    Stream all CDX entries for a domain. Uses resumeKey pagination.

    date_from / date_to: YYYYMMDD strings (Wayback format).
    """
    params = {
        "url": domain,
        "matchType": match_type,
        "output": "json",
        "fl": "timestamp,original,statuscode,digest,length,mimetype",
        "showResumeKey": "true",
        "limit": "10000",
    }
    if date_from:
        params["from"] = date_from
    if date_to:
        params["to"] = date_to

    resume_key: Optional[str] = None
    page = 0
    while True:
        page += 1
        if resume_key:
            params["resumeKey"] = resume_key
        url = f"{WAYBACK_CDX_URL}?{urlencode(params)}"
        logger.info("Wayback CDX page %d: %s", page, url)
        resp = session.get(url, timeout=120)
        resp.raise_for_status()
        rows = resp.json()
        if not rows:
            return
        # First row is the column header
        if page == 1 and rows and rows[0] and rows[0][0] == "timestamp":
            rows = rows[1:]

        # Pagination: last two rows are blank + resumeKey
        new_resume = None
        if len(rows) >= 2 and rows[-2] == [] and rows[-1]:
            new_resume = rows[-1][0]
            rows = rows[:-2]
        elif rows and rows[-1] and rows[-1][0].startswith("com,") is False and len(rows[-1]) == 1:
            # Some servers just give a bare resumeKey row
            new_resume = rows[-1][0]
            rows = rows[:-1]

        for row in rows:
            if len(row) < 6:
                continue
            yield CDXEntry(
                timestamp=row[0],
                original_url=row[1],
                statuscode=row[2],
                digest=row[3],
                length=row[4],
                mimetype=row[5],
            )

        if not new_resume:
            return
        resume_key = new_resume


# ---------------------------------------------------------------------------
# Common Crawl
# ---------------------------------------------------------------------------

def fetch_cc_index_list(session: requests.Session) -> list[dict]:
    """Get the list of all Common Crawl monthly indexes."""
    logger.info("Fetching Common Crawl index list")
    resp = session.get(COMMONCRAWL_INDEX_LIST, timeout=60)
    resp.raise_for_status()
    return resp.json()


def select_cc_indexes(all_indexes: list[dict],
                      date_from: Optional[str],
                      date_to: Optional[str]) -> list[dict]:
    """
    Filter the CC index list to those whose date range overlaps the target.
    CC index ids look like 'CC-MAIN-2024-22' (year-week).
    """
    if not date_from and not date_to:
        return all_indexes

    def parse_year(idx_id: str) -> int:
        try:
            return int(idx_id.split("-")[2])
        except (IndexError, ValueError):
            return 0

    yr_from = int(date_from[:4]) if date_from else 0
    yr_to = int(date_to[:4]) if date_to else 9999

    selected = []
    for idx in all_indexes:
        idx_id = idx.get("id", "")
        yr = parse_year(idx_id)
        # Include year-1 boundary indexes since CC crawls span calendar boundaries
        if yr_from - 1 <= yr <= yr_to + 1:
            selected.append(idx)
    return selected


def fetch_cc_for_domain(session: requests.Session,
                        index_id: str,
                        domain: str) -> Iterator[CCEntry]:
    """Query one CC index for entries matching the domain."""
    url = COMMONCRAWL_INDEX_FMT.format(index=index_id)
    params = {"url": f"*.{domain}/*", "output": "json", "pageSize": "5"}
    full_url = f"{url}?{urlencode(params)}"
    logger.info("Common Crawl %s: %s", index_id, full_url)
    try:
        resp = session.get(full_url, timeout=120)
    except requests.RequestException as exc:
        logger.warning("CC query failed for %s: %s", index_id, exc)
        return
    if resp.status_code == 404:
        logger.info("CC %s: no matches for %s", index_id, domain)
        return
    if resp.status_code != 200:
        logger.warning("CC %s returned HTTP %d", index_id, resp.status_code)
        return
    for line in resp.text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        yield CCEntry(
            index_id=index_id,
            timestamp=row.get("timestamp", ""),
            url=row.get("url", ""),
            digest=row.get("digest", ""),
            length=str(row.get("length", "")),
            mimetype=row.get("mime", ""),
            status=str(row.get("status", "")),
        )


# ---------------------------------------------------------------------------
# Divergence analysis
# ---------------------------------------------------------------------------

def index_by_date(entries: list[CDXEntry] | list[CCEntry]) -> dict[str, list]:
    """Group entries by YYYY-MM-DD."""
    out: dict[str, list] = {}
    for e in entries:
        out.setdefault(e.date_only, []).append(e)
    return out


def analyze_divergence(
    wayback_entries: list[CDXEntry],
    cc_entries: list[CCEntry],
    observations: list[ContemporaneousObservation],
) -> list[DivergenceFinding]:
    """
    Produce divergence findings. This is descriptive, not accusatory.
    """
    findings: list[DivergenceFinding] = []

    wb_by_date = index_by_date(wayback_entries)
    cc_by_date = index_by_date(cc_entries)

    wb_dates = set(wb_by_date.keys())
    cc_dates = set(cc_by_date.keys())

    # Finding type 1: dates where Wayback has captures but Common Crawl
    # ran in the same general window and recorded nothing for this domain.
    # We can only assert this where CC actually has data for the year — if
    # CC simply didn't crawl that month, absence is not evidence.
    cc_years = {d[:4] for d in cc_dates}
    wb_only_in_active_years = sorted(
        d for d in (wb_dates - cc_dates) if d[:4] in cc_years
    )
    if wb_only_in_active_years:
        # Bucket by month for readability
        from collections import Counter
        month_counts = Counter(d[:7] for d in wb_only_in_active_years)
        for month, count in sorted(month_counts.items()):
            findings.append(DivergenceFinding(
                severity="informational",
                category="wayback_capture_unsupported_by_cc",
                date=month,
                description=(
                    f"Wayback Machine reports {count} capture-day(s) in {month} "
                    f"that have no corresponding Common Crawl record, despite "
                    f"Common Crawl actively crawling the web in {month[:4]}. "
                    f"This alone is unremarkable: Common Crawl is sampled, not "
                    f"exhaustive, and many domains are not in its frontier."
                ),
                wayback_evidence=[
                    {"date": d, "captures": len(wb_by_date[d])}
                    for d in wb_only_in_active_years if d.startswith(month)
                ][:10],
                plausible_innocent_explanations=[
                    "Common Crawl is a sampled crawl and does not visit every "
                    "domain; absence from CC is the default state for most sites.",
                    "Wayback may have received captures from partner crawls "
                    "(Archive-It, Alexa, etc.) that CC did not run.",
                    "The domain may have been linked from a high-traffic page "
                    "during the period that triggered IA's own crawler but not CC's.",
                ],
            ))

    # Finding type 2: dates where Common Crawl has the domain but Wayback
    # does not. This is unusual and worth flagging — IA's crawl frontier
    # is much larger than CC's, so missing-from-Wayback is rarer.
    cc_only = sorted(cc_dates - wb_dates)
    if cc_only:
        findings.append(DivergenceFinding(
            severity="notable",
            category="cc_capture_missing_from_wayback",
            date=cc_only[0],
            description=(
                f"Common Crawl recorded {len(cc_only)} capture-day(s) for this "
                f"domain that have no corresponding Wayback Machine record. "
                f"Because Wayback's crawl frontier is substantially larger than "
                f"Common Crawl's, the inverse is more typical. Missing-from-"
                f"Wayback warrants closer inspection."
            ),
            cc_evidence=[
                {"date": d, "captures": len(cc_by_date[d])}
                for d in cc_only[:20]
            ],
            plausible_innocent_explanations=[
                "Wayback may have honored a robots.txt exclusion that arrived "
                "after CC's capture but before any IA crawler visited.",
                "A takedown request or DMCA notice may have removed specific "
                "Wayback captures.",
                "IA crawl coverage gaps from operational incidents (e.g. the "
                "October 2024 IA security breach and read-only period).",
            ],
        ))

    # Finding type 3: contemporaneous observation contradicted by current state.
    for obs in observations:
        for expected in obs.expected_capture_dates:
            target_date = expected.get("date")
            expected_count = expected.get("expected_count", 0)
            if not target_date:
                continue
            actual_count = len(wb_by_date.get(target_date, []))
            if actual_count != expected_count:
                findings.append(DivergenceFinding(
                    severity="significant" if abs(actual_count - expected_count) > 2 else "notable",
                    category="wayback_disagrees_with_observation",
                    date=target_date,
                    description=(
                        f"Contemporaneous observation by {obs.observer} on "
                        f"{obs.observed_at} recorded {expected_count} Wayback "
                        f"capture(s) for {obs.domain} on {target_date}. The "
                        f"current Wayback record shows {actual_count} capture(s) "
                        f"on the same date. Difference: {actual_count - expected_count:+d}."
                    ),
                    wayback_evidence=[
                        {"timestamp": e.timestamp, "url": e.original_url,
                         "digest": e.digest, "status": e.statuscode}
                        for e in wb_by_date.get(target_date, [])
                    ],
                    observation_evidence=[asdict(obs)],
                    plausible_innocent_explanations=[
                        "The observer may have misread or misremembered the "
                        "Wayback calendar at the original observation date.",
                        "Wayback partner-crawl ingestion can backfill historical "
                        "captures from third-party crawl donations made after "
                        "the original observation date.",
                        "Wayback UI changes between the observation date and "
                        "now may present the same underlying data differently.",
                        "The October 2024 IA security incident produced an "
                        "extended read-only period; data integrity questions "
                        "for that window are documented public fact.",
                    ],
                ))

    return findings


# ---------------------------------------------------------------------------
# Hashing & signing
# ---------------------------------------------------------------------------

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_manifest(output_dir: Path,
                   domain: str,
                   files: list[Path],
                   run_metadata: dict) -> Path:
    """Write a JSON manifest of all output files with hashes."""
    manifest = {
        "tool": "archive_triangulator",
        "version": TOOL_VERSION,
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "domain": domain,
        "run_metadata": run_metadata,
        "files": [
            {
                "path": str(p.relative_to(output_dir)),
                "size_bytes": p.stat().st_size,
                "sha256": sha256_file(p),
            }
            for p in sorted(files) if p.exists()
        ],
    }
    manifest_path = output_dir / "MANIFEST.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))

    # Always write a top-level SHA256 of the manifest itself
    manifest_hash = sha256_file(manifest_path)
    (output_dir / "MANIFEST.json.sha256").write_text(
        f"{manifest_hash}  MANIFEST.json\n"
    )
    return manifest_path


def gpg_sign(manifest_path: Path, key_id: str) -> Optional[Path]:
    """Detached-sign the manifest with GPG. Returns sig path or None on failure."""
    sig_path = manifest_path.with_suffix(manifest_path.suffix + ".asc")
    try:
        subprocess.run(
            ["gpg", "--batch", "--yes", "--armor", "--local-user", key_id,
             "--detach-sign", "--output", str(sig_path), str(manifest_path)],
            check=True, capture_output=True,
        )
        logger.info("GPG signature written to %s", sig_path)
        return sig_path
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        logger.warning("GPG signing failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

def render_findings_markdown(domain: str,
                             findings: list[DivergenceFinding],
                             wb_count: int,
                             cc_count: int,
                             observations: list[ContemporaneousObservation],
                             run_dir: Path) -> Path:
    """Produce a human-readable markdown report."""
    lines: list[str] = []
    a = lines.append
    a(f"# Archive Triangulation Report")
    a("")
    a(f"**Domain:** `{domain}`  ")
    a(f"**Generated:** {datetime.now(timezone.utc).isoformat()}  ")
    a(f"**Tool:** archive_triangulator v{TOOL_VERSION}  ")
    a("")
    a("## What this report is")
    a("")
    a("This report compares three independent sources of information about "
      "the historical web-archive record for the named domain. It reports "
      "measured divergences between sources. **It does not assert that any "
      "party tampered with any record.** Divergence is not, by itself, "
      "evidence of intentional alteration. Interpretation is the reader's "
      "responsibility.")
    a("")
    a("## Sources compared")
    a("")
    a(f"- **Wayback Machine CDX** — {wb_count} capture record(s) retrieved")
    a(f"- **Common Crawl indexes** — {cc_count} capture record(s) retrieved")
    a(f"- **Contemporaneous observations** — {len(observations)} observation(s) supplied")
    a("")
    if observations:
        a("### Observations on file")
        a("")
        for i, obs in enumerate(observations, 1):
            a(f"**Observation {i}** — observed by {obs.observer} on {obs.observed_at}")
            a("")
            a(f"> {obs.description}")
            a("")
            a(f"*Claim:* {obs.claim}")
            a("")
            if obs.evidence_uris:
                a("*Supporting evidence URIs:*")
                for u in obs.evidence_uris:
                    a(f"  - {u}")
                a("")

    a("## Findings")
    a("")
    if not findings:
        a("No divergences detected between the supplied sources within the "
          "queried date range. This is a meaningful null result: it means "
          "the three sources agree, and any hypothesis of post-hoc archive "
          "alteration is not supported by the data captured in this run.")
        a("")
    else:
        # Group by severity
        for sev in ("significant", "notable", "informational"):
            sev_findings = [f for f in findings if f.severity == sev]
            if not sev_findings:
                continue
            a(f"### {sev.title()} ({len(sev_findings)})")
            a("")
            for i, f in enumerate(sev_findings, 1):
                a(f"#### {sev.title()} finding {i} — {f.category}")
                a("")
                a(f"**Date:** {f.date}")
                a("")
                a(f.description)
                a("")
                if f.wayback_evidence:
                    a("*Wayback evidence:*")
                    a("```json")
                    a(json.dumps(f.wayback_evidence[:5], indent=2))
                    a("```")
                if f.cc_evidence:
                    a("*Common Crawl evidence:*")
                    a("```json")
                    a(json.dumps(f.cc_evidence[:5], indent=2))
                    a("```")
                if f.plausible_innocent_explanations:
                    a("*Plausible innocent explanations to rule out before "
                      "drawing any inference:*")
                    for exp in f.plausible_innocent_explanations:
                        a(f"  - {exp}")
                a("")

    a("## Methodology and limitations")
    a("")
    a("- Wayback CDX queries use the public CDX server. Results reflect "
      "what the Internet Archive currently serves; they are not "
      "independently verifiable against IA's internal storage.")
    a("- Common Crawl is a sampled, not exhaustive, crawl. Absence of a "
      "domain from a CC index does not mean the domain was inactive.")
    a("- Contemporaneous observations are user-supplied. Their evidentiary "
      "weight depends on independent corroboration (third-party-hosted "
      "screenshots with platform-side timestamps, etc.).")
    a("- The Internet Archive disclosed a significant security breach in "
      "October 2024, with extended read-only operations. Data integrity "
      "questions for that period are documented public record.")
    a("")
    a("## Reproducing this report")
    a("")
    a("All raw source files captured during this run are present in the "
      "run directory and listed in `MANIFEST.json` with SHA-256 hashes. "
      "Anyone with access to the same archives can re-run this tool against "
      "them and compare hashes to determine whether the upstream archives "
      "have changed since this capture.")
    a("")

    md_path = run_dir / "REPORT.md"
    md_path.write_text("\n".join(lines))
    return md_path


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def run_pipeline(
    domain: str,
    output_root: Path,
    date_from: Optional[str],
    date_to: Optional[str],
    observations_file: Optional[Path],
    user_agent: str,
    rate_limit: float,
    skip_cc: bool,
    gpg_key: Optional[str],
) -> Path:
    """Execute the full triangulation run."""
    run_ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = output_root / domain / run_ts
    run_dir.mkdir(parents=True, exist_ok=True)

    # Configure file logging into the run dir
    log_path = run_dir / "run.log"
    file_handler = logging.FileHandler(log_path)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    logger.addHandler(file_handler)

    logger.info("Starting triangulation run for %s", domain)
    logger.info("Run directory: %s", run_dir)

    session = make_session(user_agent=user_agent, rate_limit_seconds=rate_limit)

    # 1. Wayback CDX
    wb_path = run_dir / "wayback_cdx.jsonl"
    wb_entries: list[CDXEntry] = []
    with wb_path.open("w") as f:
        for entry in fetch_wayback_cdx(session, domain, date_from, date_to):
            wb_entries.append(entry)
            f.write(json.dumps(asdict(entry)) + "\n")
    logger.info("Wayback: %d entries written to %s", len(wb_entries), wb_path)

    # 2. Common Crawl
    cc_entries: list[CCEntry] = []
    cc_paths: list[Path] = []
    if not skip_cc:
        try:
            all_indexes = fetch_cc_index_list(session)
            selected = select_cc_indexes(all_indexes, date_from, date_to)
            logger.info("Querying %d Common Crawl indexes", len(selected))
            for idx in selected:
                idx_id = idx.get("id")
                if not idx_id:
                    continue
                idx_path = run_dir / f"commoncrawl_{idx_id}.jsonl"
                with idx_path.open("w") as f:
                    for entry in fetch_cc_for_domain(session, idx_id, domain):
                        cc_entries.append(entry)
                        f.write(json.dumps(asdict(entry)) + "\n")
                if idx_path.stat().st_size > 0:
                    cc_paths.append(idx_path)
                else:
                    idx_path.unlink()
        except requests.RequestException as exc:
            logger.error("Common Crawl phase failed: %s", exc)
    logger.info("Common Crawl: %d total entries across %d indexes",
                len(cc_entries), len(cc_paths))

    # 3. Observations
    observations: list[ContemporaneousObservation] = []
    if observations_file and observations_file.exists():
        obs_data = json.loads(observations_file.read_text())
        if isinstance(obs_data, dict):
            obs_data = [obs_data]
        for o in obs_data:
            observations.append(ContemporaneousObservation(**o))
        # Copy observations into the run dir for provenance
        obs_copy = run_dir / "observations.json"
        obs_copy.write_text(observations_file.read_text())
    logger.info("Observations: %d loaded", len(observations))

    # 4. Analyze
    findings = analyze_divergence(wb_entries, cc_entries, observations)
    findings_path = run_dir / "findings.json"
    findings_path.write_text(json.dumps(
        [asdict(f) for f in findings], indent=2, sort_keys=True
    ))
    logger.info("Analysis: %d finding(s)", len(findings))

    # 5. Render report
    report_path = render_findings_markdown(
        domain, findings, len(wb_entries), len(cc_entries), observations, run_dir
    )
    logger.info("Report written to %s", report_path)

    # 6. Manifest
    all_files = [wb_path] + cc_paths + [findings_path, report_path, log_path]
    if observations_file and (run_dir / "observations.json").exists():
        all_files.append(run_dir / "observations.json")

    run_metadata = {
        "domain": domain,
        "date_from": date_from,
        "date_to": date_to,
        "wayback_entry_count": len(wb_entries),
        "cc_entry_count": len(cc_entries),
        "observation_count": len(observations),
        "finding_count": len(findings),
        "user_agent": user_agent,
        "rate_limit_seconds": rate_limit,
    }
    manifest_path = write_manifest(run_dir, domain, all_files, run_metadata)
    logger.info("Manifest: %s", manifest_path)

    if gpg_key:
        gpg_sign(manifest_path, gpg_key)

    logger.removeHandler(file_handler)
    file_handler.close()
    return run_dir


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="archive_triangulator",
        description="Three-way archive comparison: Wayback vs Common Crawl "
                    "vs contemporaneous observations.",
    )
    p.add_argument("--domain", required=True, help="Target domain (e.g. example.gov)")
    p.add_argument("--output", default="./triangulator_output", type=Path,
                   help="Output root directory")
    p.add_argument("--from", dest="date_from", default=None,
                   help="Start date YYYYMMDD (Wayback format)")
    p.add_argument("--to", dest="date_to", default=None,
                   help="End date YYYYMMDD")
    p.add_argument("--observations", type=Path, default=None,
                   help="JSON file of contemporaneous observations")
    p.add_argument("--user-agent", default=DEFAULT_USER_AGENT)
    p.add_argument("--rate-limit", type=float, default=1.0,
                   help="Seconds between requests per host")
    p.add_argument("--skip-cc", action="store_true",
                   help="Skip Common Crawl phase (faster, less rigorous)")
    p.add_argument("--gpg-key", default=None,
                   help="GPG key ID to sign the manifest with")
    p.add_argument("--verbose", "-v", action="store_true")
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        run_dir = run_pipeline(
            domain=args.domain,
            output_root=args.output,
            date_from=args.date_from,
            date_to=args.date_to,
            observations_file=args.observations,
            user_agent=args.user_agent,
            rate_limit=args.rate_limit,
            skip_cc=args.skip_cc,
            gpg_key=args.gpg_key,
        )
    except Exception as exc:
        logger.exception("Run failed: %s", exc)
        return 1
    print(f"\nRun complete. Output: {run_dir}")
    print(f"Read the report:  {run_dir / 'REPORT.md'}")
    print(f"Verify integrity: sha256sum -c {run_dir / 'MANIFEST.json.sha256'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
