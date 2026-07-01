# F-Droid Vulnerability Analysis

This repository holds tooling and data for cloning F-Droid app repositories, scanning them
for vulnerabilities (via SAST and LLM-based analysis), and analyzing the resulting findings.

> **Every folder in this repo has its own `README.md`** with more detailed, folder-specific
> instructions. This top-level README is just an overview / map — check the folder READMEs
> before running anything inside them.

## Directory Overview

```
.
├── clone_fdroid.sh          # Script to clone the F-Droid repo(s)
├── fdroid.tar.gz            # F-Droid repo data, split/tarred to save disk space
├── fdroid_obfuscated.tar.gz # F-Droid obfuscated
│
├── results/                 # Raw scan output
│
└── analysis/                # Post-processing & analysis of results/
```

## Contents

### Cloning the F-Droid repo
The F-Droid repository is large, so instead of storing it as a live checkout, we:
1. Clone it using the provided script.
2. Split and compress the data into tarballs to save room.

See the root-level clone instructions / script comments for exact usage, and check
for any accompanying README next to the script for extraction/reassembly steps.

### `results/`
Contains the output of running vulnerability scans against the cloned apps, split into:
- **SAST results** — findings from static analysis tooling.
- **LLM results** — findings from LLM-based vulnerability review.

Both are stored as tar archives (again, to save space). See `results/README.md` for
how each subfolder is organized and how to extract/read the archives.

### `analysis/`
Takes the raw output in `results/` and analyzes it — comparing findings, computing
metrics, generating summaries/visualizations, etc. See `analysis/README.md` for
what scripts are available and how to run them.

## Getting Started

1. Run the clone script to fetch the F-Droid repo (or extract the provided tarballs).
2. Extract the relevant tarballs under `results/` for the scan type you're interested in.
3. Head into `analysis/` to run the analysis scripts against those results.

---

**Folder-level READMEs** (each with more detail):
- `results/README.md`
- `results/sast/README.md`
- `results/llm/README.md`
- `analysis/README.md`
