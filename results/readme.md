# results/

Here we have uploaded the results for further investigation.

## `validation/`

A 100-app subset used to manually validate scanner findings. This is **committed directly to the repo** — and the folders have been stored in tar files to minimize resources.

```
validation/
├── 100_results/            # the 100 anonymized apps — source, obfuscated source,
│                             # and scan results, one set per anonymized app ID
├── validation.csv           # ground-truth vulnerability labels: a manual reviewer's
│                             # verdict on each scanner finding (confirmed / false positive)
└── normal_file_names.csv    # maps each anonymized app ID to its real F-Droid package name
```

### Anonymization

App names inside `100_results/` are replaced with anonymized IDs (e.g. `app_001`,
`app_002`, ...). This protects the identity of apps with confirmed vulnerabilities —
real package names aren't publicly linked to specific findings.

`normal_file_names.csv` includes the `real_package_name` to ensure proper documnetation without giving any vulnerable information to the reader. This file is there to ensure the true names are not lost for the actual evaluation that took place.

### `validation.csv`

One row per scanner finding on a validation app, with the manual reviewer's
ground-truth verdict. [List the actual columns, e.g. `app_id, tool, finding_id,
vulnerability_type, verdict (confirmed/false_positive), reviewer_notes`.]
