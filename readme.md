# F-Droid Vulnerability Analysis

This repository holds tooling and data for cloning F-Droid app repositories, scanning them
for vulnerabilities (via SAST and LLM-based analysis), and analyzing the resulting findings.

> **Every folder in this repo has its own `README.md`** with more detailed, folder-specific
> instructions. This top-level README is just an overview / map — check the folder READMEs
> before running anything inside them.

## Data Availability

The F-Droid app data (`fdroid.tar`, `fdroid_obfuscated.tar`) and the scan results
(`results/`) are **not stored in this git repository** — they're archived on Zenodo, which
provides a permanent, citable DOI, rather than committed directly (GitHub isn't well suited
to hosting multi-GB binary archives).

**Zenodo record:** 10.5281/zenodo.21098827

To download everything into place, run:

```bash
./fetch_data.sh          # fetches all archives (apps + obfuscated + results)
./fetch_data.sh apps     # or fetch just one: apps | obfuscated | results
```

This downloads and verifies (via checksum) `fdroid.tar`, `fdroid_obfuscated.tar`, and
the `results/` archives from the Zenodo record above. See the comments at the top of
`fetch_data.sh` for how to point it at the record.

## Directory Overview

```
.
├── clone_fdroid.sh          # Script to clone the F-Droid repo(s)
├── fetch_data.sh            # Downloads fdroid.tar.gz, fdroid_obfuscated.tar.gz, and
│                             # results/ from Zenodo (see Data Availability above)
├── fdroid.tar            # F-Droid repo data, split/tarred to save disk space
│                             # (fetched via fetch_data.sh — not committed to git)
├── fdroid_obfuscated.tar # F-Droid obfuscated
│                             # (fetched via fetch_data.sh — not committed to git)
│
├── results/                 # Raw scan output (fetched via fetch_data.sh — not committed to git)
│
└── analysis/                # Post-processing & analysis of results/
```

## Contents

### Cloning the F-Droid repo

The F-Droid repository is large, so instead of storing it as a live checkout, we:

1. Clone it using the provided script.
2. Split and compress the data into tarballs to save room.
3. Archive those tarballs on Zenodo rather than committing them to git.

See the root-level clone instructions / script comments for exact usage, and check
for any accompanying README next to the script for extraction/reassembly steps.
If you just want the data as previously generated (rather than re-cloning yourself),
use `fetch_data.sh` instead of `clone_fdroid.sh` — it pulls the already-built tarballs
from Zenodo.

### `results/`

Contains the output of running vulnerability scans against the cloned apps:

- **SAST results** — findings from static analysis tooling.
- **LLM results** — findings from LLM-based vulnerability review.

Both are stored as tar archives (again, to save space) and fetched via `fetch_data.sh`.
See `results/README.md` for how each subfolder is organized and how to extract/read
the archives.

### `analysis/`

Takes the raw output in `results/` and analyzes it — comparing findings, computing
metrics, generating summaries/visualizations, etc. See `analysis/README.md` for
what scripts are available and how to run them.

## Getting Started

1. Run `./fetch_data.sh` to pull the app data and results from Zenodo (or run the
   clone script yourself to regenerate `fdroid.tar.gz` / `fdroid_obfuscated.tar.gz`
   from scratch).
2. Extract the relevant tarballs under `results/` for the scan type you're interested in.
3. Head into `analysis/` to run the analysis scripts against those results.

---

**Folder-level READMEs** (each with more detail):
- `results/README.md`
- `results/sast/README.md`
- `results/llm/README.md`
- `analysis/README.md`
