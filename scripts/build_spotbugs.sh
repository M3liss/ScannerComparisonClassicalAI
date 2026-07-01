#!/bin/bash

set -e

export ANDROID_HOME="$HOME/android-sdk"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
CODEQL_HOME="$HOME/codeql/codeql/codeql/codeql"


[ -z "$ANDROID_HOME" ] && { echo "ERROR: Set ANDROID_HOME"; exit 1; }

CODEQL_ENABLED=0
[ -n "$CODEQL_HOME" ] && [ -x "$CODEQL_HOME/codeql" ] && CODEQL_ENABLED=1

OUTPUT_BASE="${OUTPUT_BASE:-./$HOME/results1}"
SUCCESS_FILE="$HOME/build_success.txt"
FAIL_FILE="$HOME/build_failure.txt"

export ANDROID_HOME
export GRADLE_OPTS="-Dorg.gradle.daemon=false -Dorg.gradle.parallel=true"

# --------------------------
# Logging
# --------------------------
log_success() {
    (
        flock -x 200
        echo "$1|success|$(date +%s)" >> "$SUCCESS_FILE"
        echo "✓ $1"
    ) 200>"$SUCCESS_FILE.lock"
}

log_failure() {
    (
        flock -x 201
        echo "$1|$2|$(date +%s)" >> "$FAIL_FILE"
        echo "✗ $1: $2" >&2
    ) 201>"$FAIL_FILE.lock"
}

# --------------------------
# Fix missing modules (from original script)
# --------------------------
fix_missing_modules() {
    local settings_file=""
    
    [ -f "settings.gradle.kts" ] && settings_file="settings.gradle.kts"
    [ -f "settings.gradle" ] && settings_file="settings.gradle"
    [ -z "$settings_file" ] && return
    
    cp "$settings_file" "${settings_file}.bak" 2>/dev/null || true
    
    local modules=$(grep -oE ":[a-zA-Z0-9_-]+(:[a-zA-Z0-9_-]+)*" "$settings_file" | sort -u)
    
    for module in $modules; do
        local module_dir="${module#:}"
        module_dir="${module_dir//:///}"
        
        if [ ! -d "$module_dir" ]; then
            local module_escaped=$(echo "$module" | sed 's/[\/&]/\\&/g')
            sed -i "s|include[[:space:]]*[(\'\"]$module_escaped[\'\")]|// include '$module' // MISSING|g" "$settings_file"
            find . \( -name "build.gradle" -o -name "build.gradle.kts" \) -type f -exec sed -i \
                -e "s|\(implementation\|api\)[[:space:]]*project[(\'\"]$module_escaped[\'\")]|// & // MISSING|g" {} + 2>/dev/null
        fi
    done
}

# --------------------------
# Minimal gradle fixes (from original script - enhanced)
# --------------------------
minimal_gradle_fixes() {
    local gradle_file=$1
    local mode=$2  # "normal" or "obfuscated"
    
    cp "$gradle_file" "${gradle_file}.bak" 2>/dev/null || true
    
    python3 - "$gradle_file" "$mode" 2>/dev/null <<'EOF'
import sys, re
from pathlib import Path

def fix_gradle(filepath, mode):
    content = Path(filepath).read_text(encoding='utf-8', errors='ignore')
    lines = content.splitlines(keepends=True)
    output = []
    i = 0
    
    is_application = 'com.android.application' in content
    is_library = 'com.android.library' in content
    
    # Add SpotBugs plugin at start
    if i == 0:
        output.append('buildscript {\n')
        output.append('    repositories { mavenCentral(); google() }\n')
        output.append('    dependencies { classpath "com.github.spotbugs.snom:spotbugs-gradle-plugin:5.0.14" }\n')
        output.append('}\n')
        output.append('apply plugin: "com.github.spotbugs"\n')
        output.append('spotbugs { ignoreFailures = true; effort = "max"; reportLevel = "low" }\n\n')
    
    in_manifest_placeholders = False
    manifest_brace_count = 0
    
    while i < len(lines):
        line = lines[i]
        
        # For library modules, add product flavors
        if is_library and re.match(r'^\s*android\s*\{', line):
            output.append(line)
            i += 1
            check_text = ''.join(lines[i:min(i+50, len(lines))])
            if 'productFlavors' not in check_text and 'flavorDimensions' not in check_text:
                output.extend([
                    '    flavorDimensions "market"\n',
                    '    productFlavors {\n',
                    '        free { dimension "market" }\n',
                    '        play { dimension "market" }\n',
                    '    }\n'
                ])
            continue
        
        # Handle buildTypes for minification control
        if re.match(r'^\s*buildTypes\s*\{', line):
            output.append(line)
            i += 1
            
            if mode == 'obfuscated':
                # Add minification config
                output.append('        debug {\n')
                output.append('            minifyEnabled true\n')
                output.append('            shrinkResources true\n')
                output.append('            proguardFiles getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro"\n')
                output.append('        }\n')
            else:
                # Explicitly disable minification
                output.append('        debug {\n')
                output.append('            minifyEnabled false\n')
                output.append('            shrinkResources false\n')
                output.append('        }\n')
            continue
        
        # Detect manifestPlaceholders with secrets
        if re.search(r'manifestPlaceholders\s*=\s*\[', line):
            check_lines = ''.join(lines[i:min(i+10, len(lines))])
            if 'secrets' in check_lines:
                output.append('        // ' + line)
                i += 1
                in_manifest_placeholders = True
                manifest_brace_count = line.count('[') - line.count(']')
                continue
        
        if in_manifest_placeholders:
            output.append('        // ' + line)
            manifest_brace_count += line.count('[') - line.count(']')
            i += 1
            if manifest_brace_count == 0:
                in_manifest_placeholders = False
            continue
        
        # Comment out buildConfigField with secrets
        if re.search(r'buildConfigField.*secrets[\[\.]', line):
            output.append('        // ' + line)
            i += 1
            continue
        
        # Comment out signingConfigs blocks
        if re.match(r'^\s*signingConfigs\s*\{', line):
            output.append('    // ' + line)
            i += 1
            brace_count = 1
            while i < len(lines) and brace_count > 0:
                output.append('    // ' + lines[i])
                brace_count += lines[i].count('{') - lines[i].count('}')
                i += 1
            continue
        
        # Comment out flatDir blocks
        if re.match(r'^\s*flatDir\s*\{', line):
            output.append('        // ' + line)
            i += 1
            brace_count = 1
            while i < len(lines) and brace_count > 0:
                output.append('        // ' + lines[i])
                brace_count += lines[i].count('{') - lines[i].count('}')
                i += 1
            continue
        
        # Comment out gradle.taskGraph.whenReady
        if re.search(r'gradle\.taskGraph\.whenReady', line):
            output.append('    // ' + line)
            i += 1
            brace_count = line.count('{') - line.count('}')
            while i < len(lines) and brace_count > 0:
                output.append('    // ' + lines[i])
                brace_count += lines[i].count('{') - lines[i].count('}')
                i += 1
            continue
        
        # Comment out signingConfig references
        if re.search(r'^\s+signingConfig\s+signingConfigs\.', line):
            output.append(re.sub(r'^(\s*)', r'\1// ', line))
            i += 1
            continue
        
        # Add missingDimensionStrategy for applications
        if is_application and re.match(r'^\s*defaultConfig\s*\{', line):
            output.append(line)
            i += 1
            check_text = ''.join(lines[i:min(i+20, len(lines))])
            if 'missingDimensionStrategy' not in check_text:
                output.append("        missingDimensionStrategy 'market', 'free'\n")
            continue
        
        output.append(line)
        i += 1
    
    Path(filepath).write_text(''.join(output), encoding='utf-8')

if __name__ == '__main__':
    fix_gradle(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else 'normal')
EOF
}

# --------------------------
# Prepare gradle project
# --------------------------
prepare_gradle_project() {
    local mode=$1  # "normal" or "obfuscated"
    
    # Fix missing modules
    fix_missing_modules
    
    # Process all build.gradle files
    find . -type f \( -name "build.gradle" -o -name "build.gradle.kts" \) | while read gradle_file; do
        dir=$(dirname "$gradle_file")
        
        # Apply fixes with mode
        minimal_gradle_fixes "$gradle_file" "$mode"
        
        # Create local.properties
        if [ ! -f "$dir/local.properties" ] && [ -n "$ANDROID_HOME" ]; then
            echo "sdk.dir=$ANDROID_HOME" > "$dir/local.properties"
        fi
    done
    
    # Add gradle.properties
    if [ -f "gradle.properties" ]; then
        grep -q "android.suppressUnsupportedCompileSdk" "gradle.properties" || \
            echo "android.suppressUnsupportedCompileSdk=35" >> "gradle.properties"
    else
        echo "android.suppressUnsupportedCompileSdk=35" > "gradle.properties"
    fi
    
    # Create proguard-rules.pro for obfuscated builds
    if [ "$mode" = "obfuscated" ] && [ ! -f "proguard-rules.pro" ]; then
        cat > proguard-rules.pro <<'PROGUARD'
-keepattributes *Annotation*
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Application
-keep public class * extends android.app.Service
-dontwarn **
PROGUARD
    fi
}

# --------------------------
# Restore backups
# --------------------------
restore_backups() {
    find . -name "*.bak" -type f | while read backup; do
        original="${backup%.bak}"
        cp "$backup" "$original"
    done
}

# --------------------------
# Test gradle health
# --------------------------
test_gradle_health() {
    ./gradlew tasks --no-daemon >/dev/null 2>&1
}

# --------------------------
# Select Java version (from original script)
# --------------------------
select_java_for_gradle() {
    local gradle_version=$(./gradlew --version 2>/dev/null | awk '/Gradle / {print $2}')
    
    case "$gradle_version" in
        [1-6].*) export JAVA_HOME="/usr/lib/jvm/java-8-openjdk-amd64" ;;
        7.[0-5]*) export JAVA_HOME="/usr/lib/jvm/java-11-openjdk-amd64" ;;
        *) export JAVA_HOME="/usr/lib/jvm/java-17-openjdk-amd64" ;;
    esac
    
    if [ ! -x "$JAVA_HOME/bin/java" ]; then
        for jv in 17 11 8; do
            local jh="/usr/lib/jvm/java-${jv}-openjdk-amd64"
            if [ -x "$jh/bin/java" ]; then
                export JAVA_HOME="$jh"
                export PATH="$JAVA_HOME/bin:$PATH"
                return 0
            fi
        done
        return 1
    fi
    
    export PATH="$JAVA_HOME/bin:$PATH"
    return 0
}

# --------------------------
# Try gradle build variants
# --------------------------
try_gradle_build() {
    for variant in "assembleDebug" "assembleFdroidDebug" "assembleFreeDebug" "assembleFlossDebug" "assembleOssDebug" "assemble"; do
        if ./gradlew $variant --no-daemon >/dev/null 2>&1; then
            return 0
        fi
    done
    return 1
}

# --------------------------
# Build Single App
# --------------------------
build_app() {
    local app_dir=$1
    local app_name=$(basename "$app_dir")
    local output_dir="$HOME/OUTPUT_BASE/$app_name"
    
    cd "$app_dir" || { log_failure "$app_name" "cd-failed"; return 1; }
    
    # Find gradlew (search up to depth 3)
    local gradle_dir=""
    if [ -f "gradlew" ]; then
        gradle_dir="."
    else
        gradle_dir=$(find . -maxdepth 3 -name "gradlew" -type f 2>/dev/null | head -1 | xargs dirname 2>/dev/null)
    fi
    
    if [ -z "$gradle_dir" ] || [ ! -f "$gradle_dir/gradlew" ]; then
        log_failure "$app_name" "no-gradlew"
        return 1
    fi
    
    cd "$gradle_dir" || { log_failure "$app_name" "cd-gradle-failed"; return 1; }
    chmod +x gradlew
    
    # Select Java version
    select_java_for_gradle || { log_failure "$app_name" "java-selection"; return 1; }
    
    # Check if library
    local is_library=false
    grep -rq "com.android.library" --include="*.gradle*" . 2>/dev/null && is_library=true
    
    # ==========================================
    # NORMAL BUILD
    # ==========================================
    echo "[$app_name] Building normal..."
    
    prepare_gradle_project "normal"
    
    # Test health
    if ! test_gradle_health; then
        restore_backups
        if ! test_gradle_health; then
            log_failure "$app_name" "unfixable"
            return 1
        fi
    fi
    
    # Build
    if ! try_gradle_build; then
        log_failure "$app_name" "normal-build-failed"
        return 1
    fi
    
    # Collect artifacts
    mkdir -p "$output_dir/normal/apks"
    mkdir -p "$output_dir/normal/classes"
    mkdir -p "$output_dir/normal/spotbugs"
    # SpotBugs
    echo "[$app_name] SpotBugs normal..."
    ./gradlew spotbugsDebug --no-daemon >/dev/null 2>&1  || true
    find . -name "spotbugs*.xml" -path "*/reports/spotbugs/*" -exec cp {} "$output_dir/normal/spotbugs/" \; 2>/dev/null
    
    find . -name "*.apk" -path "*/outputs/apk/*" ! -name "*unsigned*" -exec cp {} "$output_dir/normal/apks/" \; 2>/dev/null
    find . -name "*.class" -path "*/intermediates/javac/*" -exec cp --parents {} "$output_dir/normal/classes/" \; 2>/dev/null
    find . -name "*.dex" -path "*/intermediates/dex/*" -exec cp {} "$output_dir/normal/classes/" \; 2>/dev/null
    
    # CodeQL
    if [ $CODEQL_ENABLED -eq 1 ]; then
        echo "[$app_name] CodeQL normal..."
        ./gradlew clean --no-daemon >/dev/null 2>&1
        
        mkdir -p "$output_dir/normal/codeql"
        $CODEQL_HOME/codeql database create "$output_dir/normal/codeql/db" \
            --language=java \
            --command="./gradlew assembleDebug --no-daemon" \
            --overwrite >/dev/null 2>&1 || true
        
        if [ -d "$output_dir/normal/codeql/db" ]; then
            $CODEQL_HOME/codeql database analyze "$output_dir/normal/codeql/db" \
                --format=sarif-latest \
                --output="$output_dir/normal/codeql/results.sarif" \
                java-security-and-quality >/dev/null 2>&1 || true
        fi
    fi
    
    # ==========================================
    # OBFUSCATED BUILD
    # ==========================================
    echo "[$app_name] Building obfuscated..."
    
    # Restore originals
    restore_backups
    
    prepare_gradle_project "obfuscated"
    
    # Build
    if ! try_gradle_build; then
        log_failure "$app_name" "obfuscated-build-failed"
        log_success "$app_name"  # Still count normal as success
        return 0
    fi
    
    # Collect artifacts
    mkdir -p "$output_dir/obfuscated/apks"
    mkdir -p "$output_dir/obfuscated/classes"
    mkdir -p "$output_dir/obfuscated/spotbugs"
    
    find . -name "*.apk" -path "*/outputs/apk/*" ! -name "*unsigned*" -exec cp {} "$output_dir/obfuscated/apks/" \; 2>/dev/null
    find . -name "*.class" -path "*/intermediates/javac/*" -exec cp --parents {} "$output_dir/obfuscated/classes/" \; 2>/dev/null
    find . -name "*.dex" -path "*/intermediates/dex/*" -exec cp {} "$output_dir/obfuscated/classes/" \; 2>/dev/null
    find . -name "mapping.txt" -path "*/outputs/mapping/*" -exec cp {} "$output_dir/obfuscated/classes/proguard-mapping.txt" \; 2>/dev/null
    
    # SpotBugs
    echo "[$app_name] SpotBugs obfuscated..."
    ./gradlew spotbugsDebug --no-daemon >/dev/null 2>&1 || true
    find . -name "spotbugs*.xml" -path "*/reports/spotbugs/*" -exec cp {} "$output_dir/obfuscated/spotbugs/" \; 2>/dev/null
    
    # CodeQL
    if [ $CODEQL_ENABLED -eq 1 ]; then
        echo "[$app_name] CodeQL obfuscated..."
        ./gradlew clean --no-daemon >/dev/null 2>&1
        
        mkdir -p "$output_dir/obfuscated/codeql"
        $CODEQL_HOME/codeql database create "$output_dir/obfuscated/codeql/db" \
            --language=java \
            --command="./gradlew assembleDebug --no-daemon" \
            --overwrite >/dev/null 2>&1 || true
        
        if [ -d "$output_dir/obfuscated/codeql/db" ]; then
            $CODEQL_HOME/codeql database analyze "$output_dir/obfuscated/codeql/db" \
                --format=sarif-latest \
                --output="$output_dir/obfuscated/codeql/results.sarif" \
                java-security-and-quality >/dev/null 2>&1 || true
        fi
    fi
    
    # Cleanup
    ./gradlew clean --no-daemon >/dev/null 2>&1 || true
    find . -name "*.bak" | xargs rm -f 2>/dev/null || true
    
    log_success "$app_name"
    return 0
}

# Export for parallel
export -f build_app log_success log_failure fix_missing_modules minimal_gradle_fixes
export -f prepare_gradle_project restore_backups test_gradle_health select_java_for_gradle try_gradle_build
export OUTPUT_BASE SUCCESS_FILE FAIL_FILE ANDROID_HOME CODEQL_ENABLED CODEQL_HOME

# Main
main() {
    local apps_dir=$1
    
    [ -z "$apps_dir" ] && { echo "Usage: $0 /path/to/apps"; exit 1; }
    [ ! -d "$apps_dir" ] && { echo "ERROR: Directory not found: $apps_dir"; exit 1; }
    
    mkdir -p "$OUTPUT_BASE"
    : > "$SUCCESS_FILE"
    : > "$FAIL_FILE"
    
    echo "=== F-Droid Build System ==="
    echo "Apps: $apps_dir"
    echo "Output: $OUTPUT_BASE"
    echo "CodeQL: $([ $CODEQL_ENABLED -eq 1 ] && echo 'enabled' || echo 'disabled')"
    echo ""
    
    find "$apps_dir" -maxdepth 1 -mindepth 1 -type d | \
        parallel -j 200 --bar build_app {}
    
    local total=$(find "$apps_dir" -maxdepth 1 -mindepth 1 -type d | wc -l)
    local success=$(wc -l < "$SUCCESS_FILE" 2>/dev/null || echo 0)
    local failed=$(wc -l < "$FAIL_FILE" 2>/dev/null || echo 0)
    
    echo ""
    echo "=== Complete ==="
    echo "Total: $total | Success: $success | Failed: $failed"
    echo "Results: $OUTPUT_BASE/"
}

main "$1"
