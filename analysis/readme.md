# analysis/

Post-processes the raw output in `results/` into the findings/metrics used in
the paper.

```
parse_files.py  →  analyze_file.py  →  aggregate_result.py
```

## `parse_files.py`

Normalizes the output from SAST and LLMs into one scheme.
```bash
python3 parse_files.py <input_dir> <output_dir>
```

## `analyze_file.py`

Analyzes all findings.
```bash
python3 analyze_file.py <input_dir> <output_dir>
```

## `aggregate_result.py`

Creates results tables.
```bash
python3 aggregate_result.py <input_dir> <output_file>
```
