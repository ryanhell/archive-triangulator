# archive_triangulator

<p align="center">
  <img src="https://raw.githubusercontent.com/ryanhell/archive-triangulator/main/banner.png" alt="archive_triangulator" width="600">
</p>

A forensic three-way comparison tool for documenting suspected post-hoc
alteration of web archive records.

## What it does

Compares three independent sources for what a domain's archive history
*should* look like:

1. **Contemporaneous observations** — your dated, externally-corroborated
   record of what an archive showed at a specific prior point in time.
2. **Current Wayback Machine CDX** — what the Internet Archive serves
   right now.
3. **Common Crawl** — what an independently-operated web archive
   recorded for the same domain.

Produces a divergence report: where do the three sources disagree?

## What it does NOT do

- **It does not assert tampering.** Divergence between sources can have
  many innocent explanations. Every flagged finding is paired with
  plausible alternative explanations the reader must rule out.
- **It does not prove anyone did anything wrong.** It produces a
  measurement. Interpretation is left to the human.
- **It does not replace contemporaneous evidence.** The strongest piece
  of evidence in any tampering investigation is the screenshot, video,
  or third-party-archived copy you captured *before* the suspected
  alteration. This tool helps you situate that evidence; it does not
  manufacture it.

## Why three sources?

A single source — even a cryptographic hash — can only prove that *the
archive currently says X*. It cannot prove what the archive said
yesterday. To establish that an archive's claims about historical
content have changed over time, you need:

- An **independent contemporaneous record** (your screenshots, posts,
  notes from the original observation date)
- A **second independent archive** (Common Crawl is operationally
  separate from the Internet Archive)
- A **current capture** of the disputed archive's claims, hashed and
  signed at capture time

When all three disagree in the same direction, the case for alteration
strengthens. When they agree, the hypothesis of alteration is not
supported, and that null result is itself a finding worth recording.

## Install

Python 3.11+. Install dependencies:

```bash
pip install -r requirements.txt
```

Optional: install `gpg` (for manifest signing) and `opentimestamps-client`
(for blockchain-anchored timestamping of manifests).

## Usage

### 1. Capture a triangulation run

```bash
python src/triangulator.py \
  --domain rivercom911.org \
  --from 20140101 \
  --to 20261231 \
  --observations examples/observations.example.json \
  --output ./output \
  --gpg-key 0xYOUR_KEY_ID
```

This produces a timestamped run directory containing:

```
output/rivercom911.org/20260508T120000Z/
  wayback_cdx.jsonl              # raw Wayback CDX response
  commoncrawl_CC-MAIN-2024-22.jsonl  # one per CC index queried
  ...
  observations.json              # copy of supplied observations
  findings.json                  # structured divergence findings
  REPORT.md                      # human-readable report
  run.log                        # full HTTP log
  MANIFEST.json                  # SHA-256 of all the above
  MANIFEST.json.sha256           # SHA-256 of the manifest itself
  MANIFEST.json.asc              # GPG signature (if --gpg-key)
```

### 2. Verify a run weeks/months later

```bash
python src/verify_run.py output/rivercom911.org/20260508T120000Z
```

Confirms every file's SHA-256 still matches the manifest, and verifies
the GPG signature if present. If anything has been altered locally
since capture, the verifier will say so and exit non-zero.

### 3. Diff two runs over time

```bash
python src/diff_runs.py \
  output/rivercom911.org/20260508T120000Z \
  output/rivercom911.org/20260601T120000Z
```

The critical output here is **digest changes on common (timestamp, url)
pairs**. A historical Wayback snapshot's `digest` field is a SHA-1 of
the captured content. If that digest changes between two runs, the
content the Wayback Machine serves for that historical timestamp has
been altered. This is the only mathematically rigorous indicator of
post-hoc archive modification, and it is exactly what this comparison
detects.

## Writing observations

The observations file is the most important input. Garbage in, garbage
out. See `examples/observations.example.json` for the schema.

Strong observations have:

- A specific, externally-verifiable timestamp (the URL of a social
  media post, an email you sent, a court filing you submitted)
- A description of *exactly what was visible on the screen* at the
  observation date — the calendar view showed N captures on date X,
  the timeline had a gap from year Y to year Z, etc.
- Links to corroborating evidence hosted on platforms outside the
  observer's control
- An explicit list of `expected_capture_dates` with the count of
  captures observed on each date, so the analyzer can compare current
  state to recorded prior state numerically

Weak observations:

- "I remember the site looked different"
- Undated claims
- Claims with no externally-verifiable corroboration

Weak observations produce weak findings. The tool will run with them
but the resulting report will be correspondingly weak.

## Methodology notes

### What the digest field actually means

The Wayback CDX `digest` field is the base32-encoded SHA-1 of the
captured response body at the time of capture. It is supposed to be
immutable. If you have a CDX entry from a prior run with digest `XYZ`
for `(timestamp=20240704120000, url=https://example.gov/policy)`, and
a later CDX query for the same `(timestamp, url)` returns digest
`ABC`, then the underlying stored capture has been replaced. There is
no innocent explanation for digest churn on truly-historical snapshots
of static content. (For dynamic content with embedded timestamps,
digests can vary on re-render; this tool reports the change but the
human must judge.)

### What "appeared" between runs means

Captures appearing in a later run that were absent in an earlier run
can have legitimate explanations:

- **Partner crawl backfill**: IA periodically ingests crawl data
  donated by Archive-It, Common Crawl, Alexa, and others. These
  ingestions can populate the calendar with historical captures that
  were not visible on the IA calendar at an earlier date even though
  the underlying captures existed elsewhere.
- **Index rebuild**: IA occasionally rebuilds CDX indexes, surfacing
  captures that existed in storage but were not previously indexed.
- **Coverage expansion**: The IA crawl frontier expands over time;
  domains added to the frontier later may show retroactive captures
  from continuous-crawl partners.

A flurry of "appeared" captures concentrated around a specific
sensitive date is suggestive but not dispositive. Look for the digest
content of those captures — does it match what would have been on the
live site at that historical date, or does it match the *current*
site frozen in time?

### The October 2024 IA security incident

The Internet Archive disclosed a significant data breach in October
2024 with 31 million records exposed and an extended read-only
operating mode. This is documented public fact. Any analysis of
Wayback data integrity for the period spanning that incident must
acknowledge it as a confounding variable. This is not conspiracy
framing — it is professional caution.

## Legal / evidentiary notes

This tool is designed to produce output that may be used in litigation,
investigative journalism, or regulatory complaints. To preserve
evidentiary value:

- Run on a clean machine with documented system state
- Keep the GPG signing key offline; sign manifests on a system not
  connected to the network during signing
- Store run directories on write-once media (or on a filesystem with
  immutable attributes set after capture)
- Maintain a chain-of-custody log alongside the runs

This is general guidance, not legal advice. Consult a lawyer about
admissibility in your jurisdiction.

## License

AGPL-3.0. If you fork or modify this tool and run it as a service,
you must publish your modifications.

## Reporting issues

This tool is provided as-is. Bugs, false positives, and methodology
concerns should be reported via the project issue tracker.
