# scripts/

Runners for each static analysis / vulnerability scanning tool. Each detects
vulnerabilities in the dataset (`fdroid.tar.gz` and `fdroid_obfuscated.tar.gz`,
extracted) and writes its output into `results/`.

## `build_spotbugs.sh`

Builds the app, then runs SpotBugs on the build output to detect vulnerabilities.

```bash
./build_spotbugs.sh <app_path> <output_dir>
```

## `codeql_runner.sh`

Runs CodeQL to detect vulnerabilities.

```bash
./codeql_runner.sh <app_path> <output_dir>
```

## `semgrep_run.py`

Runs Semgrep to detect vulnerabilities.

```bash
python3 semgrep_run.py <app_path> <output_dir>
```

## `sonarqube.sh`

Runs SonarQube to detect vulnerabilities.

```bash
./sonarqube.sh <app_path> <output_dir>
```

## `vusc_runner.sh`

Runs [VUSC — tool name/what it stands for] to detect vulnerabilities.

```bash
./vusc_runner.sh <app_path> <output_dir>
```
