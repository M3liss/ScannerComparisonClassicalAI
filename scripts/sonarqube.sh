#!/bin/bash

source test/bin/activate
export PATH=$PATH:~/Dokumente/sonar-scannerCLI/bin

APPS_ROOT="downloaded_results"  # e.g. /home/mel46487/fdroid_extracted
SONAR_TOKEN="sqa_cc01fec36748d647fcbf8765d871754d7930ed30"
RESOURCE_FILE_OBFUSCATED="/home/mel46487/Dokumente/resources_sonarqube_obfuscated.csv"
RESOURCE_FILE_NORMAL="/home/mel46487/Dokumente/resources_sonarqube_normal.csv"
csv_lock=$(mktemp)

# Make sure CSV headers exist
[[ ! -f "$RESOURCE_FILE_NORMAL" ]] && echo "app_id,elapsed_sec,rss_mb" > "$RESOURCE_FILE_NORMAL"
[[ ! -f "$RESOURCE_FILE_OBFUSCATED" ]] && echo "app_id,elapsed_sec,rss_mb" > "$RESOURCE_FILE_OBFUSCATED"

analyze_app() {
    local app_dir="$1"
    local app_type="$2"
    local app_id
    app_id=$(basename "$app_dir")
    local classes_dir="${app_type}_classes"
    local time_file
    time_file=$(mktemp)

    # Skip if no classes
    if [[ ! -d "$app_dir/$classes_dir" ]]; then
        echo "[$app_id] Skipping: no classes/ directory found" >&2
        rm -f "$time_file"
        return 1
    fi

    json_file="sonar_${app_type}.json"

    if [[ -f "${app_dir}/$json_file" ]]; then
    echo "Analysis already done for ${app_dir}"
        return 0   # or exit 0 if in main script
    fi

    local props_file="$app_dir/sonar-project.properties"

    # Write sonar-project.properties
    cat > "$props_file" <<EOF
sonar.projectKey=fdroid-${app_id}-${app_type}
sonar.projectName=$app_id
sonar.projectVersion=1.0
sonar.java.binaries=$classes_dir
sonar.sourceEncoding=UTF-8
sonar.exclusions=**/test/**,**/generated/**
sonar.qualitygate.wait=false
sonar.security.config=owasp
EOF

    # Run scanner and time it
    cd "$app_dir" || return 1
    (
        /usr/bin/time -f "elapsed_sec=%e\nmax_rss_kb=%M" -o "$time_file" \
            sonar-scanner \
                -Dsonar.host.url=http://localhost:9000 \
                -Dsonar.token="$SONAR_TOKEN" \
                #> /dev/null 2>&1
    )
    scanner_rc=$?
    # Read metrics
    local elapsed rss_kb rss_mb
    elapsed=$(awk -F= '/elapsed_sec/ {print $2}' "$time_file")
    rss_kb=$(awk -F= '/max_rss_kb/ {print $2}' "$time_file")
    rss_mb=$(echo "scale=2; $rss_kb / 1024" | bc)
    rm -f "$time_file"

    # Write CSV safely
    if [[ "$app_type" == "normal" ]]; then
        echo "$app_id,$elapsed,$rss_mb" >> "$RESOURCE_FILE_NORMAL"
    else
        echo "$app_id,$elapsed,$rss_mb" >> "$RESOURCE_FILE_OBFUSCATED"
    fi
    # If scanner succeeded, fetch issues
    if [ "$scanner_rc" -eq 0 ]; then
        rm -f "$props_file"

        # Wait for SonarQube to process issues (up to 1 min)
        for i in {1..12}; do
            total=$(curl -s -u "$SONAR_TOKEN:" \
                "http://localhost:9000/api/issues/search?componentKeys=fdroid-${app_id}-${app_type}&ps=1" \
                | jq -r '.total')
            [[ "$total" != "0" ]] && break
        done

        # Fetch all issues silently
        curl -s -u "$SONAR_TOKEN:" \
            "http://localhost:9000/api/issues/search?componentKeys=fdroid-${app_id}-${app_type}&ps=500" \
            -o "sonar_${app_type}.json" 2>/dev/null
    else
        rm -f "$props_file"
        echo "[$app_id-$app_type] Scanner failed" >&2
    fi

    cd ..
    cd ..
}

# Start SonarQube
./sonar-scanner/bin/linux-x86-64/sonar.sh start

MAX_JOBS=2
running=0

for app_dir in "$APPS_ROOT"/*; do
    (
        analyze_app "$app_dir" "normal"
        analyze_app "$app_dir" "obfuscated"
    ) &

    ((running++))
    if (( running >= MAX_JOBS )); then
        wait -n
        ((running--))
    fi
done

wait

./sonar-scanner/bin/linux-x86-64/sonar.sh stop

rm -f "$csv_lock"
