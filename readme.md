# F-Droid Vulnerability Analysis

This repository holds tooling and data for cloning F-Droid app repositories, scanning them
for vulnerabilities (via SAST and LLM-based analysis), and analyzing the resulting findings.

> **Every folder in this repo has its own `README.md`** with more detailed, folder-specific
> instructions. This top-level README is just an overview / map — check the folder READMEs
> before running anything inside them.

## Data Availability

We provide the anonymized results of the 100 manually validated apps inside this repository under `results`. For safety, we do not enclose the true repositories names, but include a mapping file of the true names used in this study.

- `100_results/` — the 100 anonymized apps: source code, obfuscated source code,
  and scan results, with real app names replaced by anonymized IDs (`app_001`, ...)
  to protect the identity of apps with confirmed vulnerabilities
- `validation.csv` — ground-truth vulnerability labels: a manual reviewer's verdict
  (confirmed / false positive) on each scanner finding
- `normal_file_names.csv` — maps each anonymized ID back to its real F-Droid
  package name

See `results/README.md` for the full anonymization scheme and how to de-anonymize
when needed.

## Directory Overview

```
.
├── clone_fdroid.sh          # Script to clone the F-Droid repo(s)
├── fetch_data.sh            # Downloads fdroid.tar, fdroid_obfuscated.tar, and
│                             # results/{sast,llm}/ from Zenodo (see Data Availability above)
├── fdroid.tar                # F-Droid repo data, split/tarred to save disk space
│                             # (fetched via fetch_data.sh — not committed to git)
├── fdroid_obfuscated.tar     # F-Droid obfuscated
│                             # (fetched via fetch_data.sh — not committed to git)
│
├── results/
│   └── validation/           # committed directly to git (anonymized, no Zenodo)
│       ├── 100_results/
│   ├── validation.csv
│   ├── normal_file_names.csv
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

- **SAST results** (`results/sast/`) — findings from static analysis tooling, fetched via `fetch_data.sh`.
- **LLM results** (`results/llm/`) — findings from LLM-based vulnerability review, fetched via `fetch_data.sh`.
- **Validation subset** (`results/validation/`) — anonymized 100-app subset used to
  validate scanner findings, committed directly to this repo (no Zenodo).

See `results/README.md` for how each subfolder is organized and how to extract/read
the archives.

### `analysis/`

Takes the raw output in `results/` and analyzes it — comparing findings, computing
metrics, generating summaries/visualizations, etc. See `analysis/README.md` for
what scripts are available and how to run them.

## Getting Started

1. Run `./fetch_data.sh` to pull the app data and full results from Zenodo (or run
   the clone script yourself to regenerate `fdroid.tar` / `fdroid_obfuscated.tar`
   from scratch). The validation subset in `results/validation/` is already in the
   repo — no fetch needed.
2. Extract the relevant tarballs under `results/` for the scan type you're interested in.
3. Head into `analysis/` to run the analysis scripts against those results.

---

**Folder-level READMEs** (each with more detail):
- `results/README.md`
- `results/sast/README.md`
- `results/llm/README.md`
- `analysis/README.md`
