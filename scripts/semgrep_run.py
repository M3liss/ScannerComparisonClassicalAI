#!/bin/bash
source ~/test/bin/activate

PARENT_DIR="fdroid_apps_obfuscated"
RESULTS_DIR="results"
RESOURCE_LOG_CSV="semgrep_resource_usage_obfuscated.csv"

mkdir -p "$RESULTS_DIR"

if [ ! -f "$RESOURCE_LOG_CSV" ]; then
    echo "project,elapsed_time_sec,max_memory_kb,exit_code,lines_of_code,num_files" > "$RESOURCE_LOG_CSV"
fi

scan_dir() {
    dir="$1"
    dir_name=$(basename "$dir")
    output_subdir="${RESULTS_DIR}/${dir_name}"

    if [ ! -d "$PARENT_FIR/$dir_name}/sources/sources" ]; then
        return 1   # use `exit 1` if this is in a script, `return 1` if inside a function
    fi

    cd sources/sources/a2dp/Vol



    
    output_file="${output_subdir}/semgrep_obfuscated.sarif"
    
    start_time_ns=$(date +%s%N)
    
    # Run Semgrep with comprehensive security rulesets
    time_output=$( { /usr/bin/time -v semgrep \
        --config=p/security-audit \
        --config=p/java \
        --config=p/kotlin \
        --config=p/secrets \
        --config=p/owasp-top-ten \
        --sarif-output="$output_file" \
        --include="*.java" \
        --include="*.kt" \
        --include="*.xml" \
        --exclude="build/" \
        --exclude="gradle/" \
        --exclude=".gradle/" \
        --exclude="gradlew" \
        --exclude="gradlew.bat" \
        --exclude="*.gradle" \
        --metrics=off \
        --quiet \
        "$dir" > /dev/null 2>&1; } 2>&1 )
    
    ret_code=$?
    
    end_time_ns=$(date +%s%N)
    elapsed_time=$(echo "scale=3; ($end_time_ns - $start_time_ns)/1000000000" | bc)
    
    max_mem_kb=$(echo "$time_output" | grep "Maximum resident set size" | awk -F: '{print $2}' | xargs)
    
    if [ -z "$max_mem_kb" ]; then
        max_mem_kb=0
    fi

    cd ..
    cd ..
    cd ..
    cd ..
    
    {
        echo "$dir_name,$elapsed_time,$max_mem_kb,$ret_code,$loc,$num_files"
    } >> "$RESOURCE_LOG_CSV"
    
    echo "[✓] $dir_name (LOC: $loc, Files: $num_files, Time: ${elapsed_time}s)"
}

export -f scan_dir
export RESULTS_DIR RESOURCE_LOG_CSV

echo "=========================================="
echo "Starting Semgrep scan on all apps"
echo "Rulesets: security-audit, java, kotlin, secrets, owasp-top-ten"
echo "=========================================="
echo ""

# Run in parallel
find "$PARENT_DIR" -mindepth 1 -maxdepth 1 -type d \
    | parallel -j 50 scan_dir {}

echo ""
echo "=========================================="
echo "✅ All scans complete!"
echo "Results: $RESULTS_DIR"
echo "CSV: $RESOURCE_LOG_CSV"
echo "=========================================="
echo ""
echo "Quick stats:"
echo "  Total apps: $(tail -n +2 $RESOURCE_LOG_CSV | wc -l)"
echo "  Avg time: $(tail -n +2 $RESOURCE_LOG_CSV | awk -F, '{sum+=$2; count++} END {printf "%.2f", sum/count}')s"
echo "  Avg LOC: $(tail -n +2 $RESOURCE_LOG_CSV | awk -F, '{sum+=$5; count++} END {printf "%.0f", sum/count}')"
