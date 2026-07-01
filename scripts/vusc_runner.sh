#!/bin/bash
set -euo pipefail

# ----------------------
# Configuration
# ----------------------
RUNNER="./AnalysisStandaloneRunner/AnalysisStandaloneRunner"
CONFIG="/AnalysisStandaloneRunner/server.conf"
RESULTS_DIR="downloaded_results"
RESOURCE_FILE_NORMAL="resources_vusc_normal.csv"
RESOURCE_FILE_OBFUSCATED="resources_vusc_obfuscated.csv"
MAX_APPS_PARALLEL=5

# ----------------------
# Initialize CSVs (append-safe)

csv_lock=$(mktemp)

# ----------------------
# Analyze a single APK
# ----------------------
analyze_apk() {
    local app_name="$1"
    local apk_type="$2"
    local apk_path="$RESULTS_DIR/$app_name/${apk_type}.apk"
    local output_dir="$RESULTS_DIR/$app_name"
    local time_file
    time_file=$(mktemp)

    [[ -f "$apk_path" ]] || {
        echo "[$app_name][$apk_type] APK not found"
        return
    }

    if [ -f "$output_dir/vusc_${apk_type}.json" ]; then
        return
    fi
    
    echo "[$app_name][$apk_type] starting"

    /usr/bin/time -f "elapsed_sec=%e\nmax_rss_kb=%M" -o "$time_file" \
    "$RUNNER" --configfile "$CONFIG" --output "$output_dir" "$apk_path" \
    >/dev/null 2>&1 || {
        echo "[$app_name][$apk_type] Runner failed"
        return 1
    }

    local elapsed rss_kb rss_mb
    elapsed=$(grep elapsed_sec "$time_file" | cut -d= -f2)
    rss_kb=$(grep max_rss_kb "$time_file" | cut -d= -f2)
    rss_mb=$(echo "scale=2; $rss_kb / 1024" | bc)

    {
        flock 200
        if [[ "$apk_type" == "normal" ]]; then
            echo "$app_name,$elapsed,$rss_mb" >> "$RESOURCE_FILE_NORMAL"
        else
            echo "$app_name,$elapsed,$rss_mb" >> "$RESOURCE_FILE_OBFUSCATED"
        fi
    } 200>"$csv_lock"

    rm -f "$time_file"

    
    json_file=$(find "$output_dir" -name "${apk_type}.apk_*.json" -type f | head -n1)
    [[ -n "$json_file" ]] && mv "$json_file" "$output_dir/vusc_${apk_type}.json"

    echo "[$app_name][$apk_type] done"
}

# ----------------------
# Process one app (SEQUENTIAL)
# ----------------------
process_app() {
    local app_name="$1"

    analyze_apk "$app_name" normal
    analyze_apk "$app_name" obfuscated
}

# ----------------------
# Main loop (parallel apps)
# ----------------------
echo "Starting analysis of apps in $RESULTS_DIR with up to $MAX_APPS_PARALLEL parallel apps..."

for app_dir in "$RESULTS_DIR"/*/; do
    app_name=$(basename "$app_dir")

    # Flatten nested folder
    if [[ -d "$app_dir/$app_name" ]]; then
        mv "$app_dir/$app_name"/* "$app_dir/" 2>/dev/null || true
        rmdir "$app_dir/$app_name" 2>/dev/null || true
    fi

    # Throttle parallel apps
    while (( $(jobs -rp | wc -l) >= MAX_APPS_PARALLEL )); do
        sleep 0.2
    done

    process_app "$app_name" &
done

wait
rm -f "$csv_lock"

echo ""
echo "Analysis complete!"
echo "Normal APK results: $RESOURCE_FILE_NORMAL"
echo "Obfuscated APK results: $RESOURCE_FILE_OBFUSCATED"
