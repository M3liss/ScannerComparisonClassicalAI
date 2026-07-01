#!/bin/bash
#
# run_codeql.sh - Run CodeQL analysis on normal and obfuscated builds
#
# CodeQL analyzes source code by creating a database during compilation.
# We need to run CodeQL during/after each build type to capture the
# appropriate code state (normal vs obfuscated identifiers in source).
#
# Usage: ./run_codeql.sh <app_directory> [build_type]
#   build_type: normal, obfuscated, or both (default: both)
#
CODEQL_PATH="$HOME/codeql/codeql/codeql/codeql"

APP_DIR="$1"
BUILD_TYPE="${2:-both}"

if [ -z "$APP_DIR" ]; then
    echo "Usage: $0 <app_directory> [build_type]"
    echo "  build_type: normal, obfuscated, or both (default: both)"
    exit 1
fi

if [ "$BUILD_TYPE" != "normal" ] && [ "$BUILD_TYPE" != "obfuscated" ] && [ "$BUILD_TYPE" != "both" ]; then
    echo "Error: build_type must be 'normal', 'obfuscated', or 'both'"
    exit 1
fi

cd "$APP_DIR" || exit 1
APP_NAME=$(basename "$APP_DIR")

# Setup directories
RESULTS_DIR="results"
CODEQL_DIR="$RESULTS_DIR/codeql_reports"
CODEQL_DBS_DIR="$RESULTS_DIR/codeql_databases"

mkdir -p "$CODEQL_DIR" "$CODEQL_DBS_DIR"

# Log file
LOG_FILE="$RESULTS_DIR/codeql_log.txt"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting CodeQL: $APP_NAME ($BUILD_TYPE)" >> "$LOG_FILE"

# CSV file
CSV_FILE="$RESULTS_DIR/codeql_metrics.csv"
if [ ! -f "$CSV_FILE" ]; then
    echo "App,BuildType,DatabaseCreationTime,AnalysisTime,TotalTime,AlertCount,ErrorCount,WarningCount,NoteCount,AnalysisDate" > "$CSV_FILE"
fi

# Setup Gradle
export PATH="$HOME/gradle-7.6.3/bin:$PATH"
pkill -f gradle 2>/dev/null

detect_module() {
    if [ -f "./AndroidManifest.xml" ]; then
        echo "."
        return
    fi
    
    local manifest=$(find . -maxdepth 4 -name "AndroidManifest.xml" -path "*/main/*" 2>/dev/null | head -1)
    
    if [ -n "$manifest" ]; then
        local module=$(echo "$manifest" | sed 's|^\./||' | cut -d'/' -f1)
        if [ "$module" != "AndroidManifest.xml" ] && [ -d "$module" ]; then
            echo "$module"
            return
        fi
    fi
    
    manifest=$(find . -maxdepth 4 -name "AndroidManifest.xml" 2>/dev/null | head -1)
    if [ -n "$manifest" ]; then
        local manifest_dir=$(dirname "$manifest")
        local module=$(echo "$manifest_dir" | sed 's|^\./||' | cut -d'/' -f1)
        if [ "$module" != "AndroidManifest.xml" ] && [ -n "$module" ] && [ "$module" != "." ]; then
            echo "$module"
            return
        fi
    fi
    
    local build_gradle=$(find . -maxdepth 2 -name "build.gradle" -type f 2>/dev/null | grep -v "^\./build.gradle$" | head -1)
    if [ -n "$build_gradle" ]; then
        local module=$(dirname "$build_gradle" | sed 's|^\./||')
        echo "$module"
        return
    fi
    echo "app"
}

detect_library_type() {
    if grep -r "androidx\." . --include="*.java" --include="*.kt" -q 2>/dev/null; then
        echo "androidx"
    elif grep -r "android\.support\." . --include="*.java" --include="*.kt" -q 2>/dev/null; then
        echo "support"
    else
        echo "unknown"
    fi
}

detect_package() {
    local manifest=$(find . -name "AndroidManifest.xml" -path "*/main/*" 2>/dev/null | head -1)
    [ -z "$manifest" ] && manifest=$(find . -name "AndroidManifest.xml" 2>/dev/null | head -1)
    grep -oP 'package="\K[^"]+' "$manifest" 2>/dev/null | head -1
}

detect_source_sets() {
    local module="$1"
    local manifest=$(find . -name "AndroidManifest.xml" -path "*/${module}/*" 2>/dev/null | head -1)
    
    if [ -z "$manifest" ]; then
        manifest=$(find . -name "AndroidManifest.xml" 2>/dev/null | head -1)
    fi
    
    if [ -n "$manifest" ]; then
        local manifest_dir=$(dirname "$manifest")
        local relative_path=$(echo "$manifest_dir" | sed "s|^\./||" | sed "s|^${module}||" | sed "s|^/||")
        
        if [ -z "$relative_path" ] || [ "$relative_path" = "." ]; then
            echo "OLD_STYLE:"
        elif echo "$relative_path" | grep -q "/main"; then
            echo "MODERN:$(echo "$relative_path" | sed 's|/main.*||')"
        else
            echo "OLD_STYLE:$relative_path"
        fi
    else
        echo "MODERN:"
    fi
}

clean_project() {
    rm -rf .gradle build */build 2>/dev/null
    rm -f build.gradle */build.gradle settings.gradle gradle.properties local.properties 2>/dev/null
    rm -f */proguard-rules.pro proguard-rules.pro 2>/dev/null
}

create_build_files() {
    local java_version="$1"
    local compile_sdk="$2"
    local use_androidx="$3"
    local minify="$4"
    local module="$5"
    
    local package_name=$(detect_package)
    local source_info=$(detect_source_sets "$module")
    local style=$(echo "$source_info" | cut -d: -f1)
    local source_path=$(echo "$source_info" | cut -d: -f2)
    
    local build_file
    if [ "$module" = "." ]; then
        build_file="build.gradle"
    else
        mkdir -p "$module"
        build_file="$module/build.gradle"
    fi

    # Root build.gradle
    if [ "$module" != "." ]; then
        cat > build.gradle << 'EOF'
buildscript {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
    dependencies {
        classpath 'com.android.tools.build:gradle:7.4.2'
    }
}

allprojects {
    repositories {
        google()
        mavenCentral()
    }
}

task clean(type: Delete) {
    delete rootProject.buildDir
}
EOF
    fi

    # settings.gradle
    if [ "$module" = "." ]; then
        cat > settings.gradle << 'EOF'
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.PREFER_SETTINGS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = 'app'
EOF
    else
        cat > settings.gradle << EOF
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.PREFER_SETTINGS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = 'app'
include ':$module'
EOF
    fi

    # gradle.properties
    if [ "$use_androidx" = "true" ]; then
        cat > gradle.properties << 'EOF'
android.useAndroidX=true
android.enableJetifier=true
org.gradle.jvmargs=-Xmx4096m
EOF
    else
        cat > gradle.properties << 'EOF'
android.useAndroidX=false
android.enableJetifier=false
org.gradle.jvmargs=-Xmx4096m
EOF
    fi

    echo "sdk.dir=$ANDROID_HOME" > local.properties

    # Module build.gradle
    if [ "$module" = "." ]; then
        cat > $build_file << EOF
buildscript {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
    dependencies {
        classpath 'com.android.tools.build:gradle:7.4.2'
    }
}

apply plugin: 'com.android.application'

android {
    namespace '$package_name'
    compileSdk $compile_sdk

    defaultConfig {
        applicationId "$package_name"
        minSdk 21
        targetSdk $compile_sdk
        versionCode 1
        versionName "1.0"
    }
EOF
    else
        cat > $build_file << EOF
plugins {
    id 'com.android.application'
}

android {
    namespace '$package_name'
    compileSdk $compile_sdk

    defaultConfig {
        applicationId "$package_name"
        minSdk 21
        targetSdk $compile_sdk
        versionCode 1
        versionName "1.0"
    }
EOF
    fi

    # Source sets
    if [ "$style" = "OLD_STYLE" ]; then
        if [ -n "$source_path" ]; then
            cat >> $build_file << EOF

    sourceSets {
        main {
            manifest.srcFile '$source_path/AndroidManifest.xml'
            java.srcDirs = ['$source_path/src', '$source_path/java']
            res.srcDirs = ['$source_path/res']
            assets.srcDirs = ['$source_path/assets']
        }
    }
EOF
        else
            cat >> $build_file << EOF

    sourceSets {
        main {
            manifest.srcFile 'AndroidManifest.xml'
            java.srcDirs = ['src', 'java']
            res.srcDirs = ['res']
            assets.srcDirs = ['assets']
        }
    }
EOF
        fi
    elif [ "$style" = "MODERN" ] && [ -n "$source_path" ]; then
        cat >> $build_file << EOF

    sourceSets {
        main {
            manifest.srcFile '$source_path/main/AndroidManifest.xml'
            java.srcDirs = ['$source_path/main/java']
            res.srcDirs = ['$source_path/main/res']
            assets.srcDirs = ['$source_path/main/assets']
        }
    }
EOF
    fi

    cat >> $build_file << EOF

    buildTypes {
        release {
            minifyEnabled $minify
            shrinkResources $minify
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
        }
        debug {
            minifyEnabled false
        }
    }

    compileOptions {
        sourceCompatibility JavaVersion.$java_version
        targetCompatibility JavaVersion.$java_version
    }

    lint {
        abortOnError false
        checkReleaseBuilds false
    }
}

dependencies {
    implementation fileTree(dir: 'libs', include: ['*.jar'])
EOF

    if [ "$use_androidx" = "true" ]; then
        cat >> $build_file << 'EOF'
    
    implementation 'androidx.appcompat:appcompat:1.6.1'
    implementation 'androidx.core:core:1.10.1'
    implementation 'com.google.android.material:material:1.9.0'
    implementation 'androidx.constraintlayout:constraintlayout:2.1.4'
    implementation 'androidx.preference:preference:1.2.0'
EOF
    else
        cat >> $build_file << 'EOF'
    
    implementation 'com.android.support:appcompat-v7:28.0.0'
    implementation 'com.android.support:support-v4:28.0.0'
    implementation 'com.android.support:design:28.0.0'
    implementation 'com.android.support:preference-v7:28.0.0'
    implementation 'com.android.support:support-annotations:28.0.0'
    implementation 'com.android.support.constraint:constraint-layout:1.1.3'
EOF
    fi

    cat >> $build_file << 'EOF'
}

configurations.all {
    resolutionStrategy {
        force 'org.jetbrains.kotlin:kotlin-stdlib:1.8.10'
        force 'org.jetbrains.kotlin:kotlin-stdlib-jdk7:1.8.10'
        force 'org.jetbrains.kotlin:kotlin-stdlib-jdk8:1.8.10'
    }
}
EOF

    # ProGuard rules (same as your original)
    local proguard_file
    if [ "$module" = "." ]; then
        proguard_file="proguard-rules.pro"
    else
        proguard_file="$module/proguard-rules.pro"
    fi
    
    if [ "$minify" = "true" ]; then
        cat > $proguard_file << 'EOF'
-repackageclasses ''
-allowaccessmodification
-dontpreverify
-optimizationpasses 5

-keep public class * extends android.app.Activity
-keep public class * extends android.app.Application
-keep public class * extends android.app.Service
-keep public class * extends android.content.BroadcastReceiver
-keep public class * extends android.content.ContentProvider

-keepclasseswithmembers class * {
    public <init>(android.content.Context, android.util.AttributeSet);
}

-keepclasseswithmembernames class * {
    native <methods>;
}

-keep class * implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator *;
}

-keep class android.support.** { *; }
-keep class androidx.** { *; }
-dontwarn android.support.**
-dontwarn androidx.**

-keepattributes *Annotation*
-keepattributes Signature
-verbose
EOF
    else
        cat > $proguard_file << EOF
-keep class $package_name.** { *; }
-keep class android.support.** { *; }
-keep class androidx.** { *; }
-dontwarn android.support.**
-dontwarn androidx.**
-keepattributes *Annotation*
-verbose
EOF
    fi
}

run_codeql_analysis() {
    local java_version="$1"
    local compile_sdk="$2"
    local use_androidx="$3"
    local minify="$4"
    local build_type="$5"
    local desc="$6"
    local module="$7"
    
    clean_project
    create_build_files "$java_version" "$compile_sdk" "$use_androidx" "$minify" "$module"
    
    local task_prefix
    if [ "$module" = "." ]; then
        task_prefix=""
    else
        task_prefix=":${module}"
    fi
    
    local task="${task_prefix}:assembleDebug"
    [ "$minify" = "true" ] && task="${task_prefix}:assembleRelease"
    
    export JAVA_HOME="$JAVA11_HOME"
    export PATH="$JAVA_HOME/bin:$HOME/gradle-7.6.3/bin:$PATH"
    
    local db_name="${APP_NAME}_${build_type}_db"
    local db_path="$CODEQL_DBS_DIR/$db_name"
    
    # Remove old database
    rm -rf "$db_path"
    
    echo "Creating CodeQL database for $build_type build..."
    
    # Step 1: Create database (traces build)
    local db_start=$(date +%s)
    
    if $CODEQL_PATH database create "$db_path" \
        --language=java \
        --command="gradle $task --no-daemon" \
        --source-root=. \
        > codeql_db.log 2>&1; then
        
        local db_end=$(date +%s)
        local db_time=$((db_end - db_start))
        
        echo "Database created in ${db_time}s. Running analysis..."
        
        # Step 2: Analyze database
        local analysis_start=$(date +%s)
        
        local sarif_output="$CODEQL_DIR/${APP_NAME}_${build_type}_codeql.sarif"
        local csv_output="$CODEQL_DIR/${APP_NAME}_${build_type}_codeql.csv"
        
        if $CODEQL_PATH database analyze "$db_path" \
            --format=sarif-latest \
            --output="$sarif_output" \
            --sarif-category=java \
            -- \
            > codeql_analysis.log 2>&1; then
            
            local analysis_end=$(date +%s)
            local analysis_time=$((analysis_end - analysis_start))
            local total_time=$((db_time + analysis_time))
            
            # Parse SARIF for counts
            local alert_count=0
            local error_count=0
            local warning_count=0
            local note_count=0
            
            if command -v jq &> /dev/null && [ -f "$sarif_output" ]; then
                alert_count=$(jq '[.runs[].results[]] | length' "$sarif_output" 2>/dev/null || echo 0)
                error_count=$(jq '[.runs[].results[] | select(.level=="error")] | length' "$sarif_output" 2>/dev/null || echo 0)
                warning_count=$(jq '[.runs[].results[] | select(.level=="warning")] | length' "$sarif_output" 2>/dev/null || echo 0)
                note_count=$(jq '[.runs[].results[] | select(.level=="note")] | length' "$sarif_output" 2>/dev/null || echo 0)
            fi
            
            # Create metrics file
            cat > "$CODEQL_DIR/${APP_NAME}_${build_type}_metrics.txt" << EOF
App: $APP_NAME
Build Type: $build_type
Build Configuration: $desc
Module: $module
Database Creation Time: ${db_time}s
Analysis Time: ${analysis_time}s
Total Time: ${total_time}s
Total Alerts: $alert_count
Errors: $error_count
Warnings: $warning_count
Notes: $note_count
Analysis Date: $(date)
Database Location: $db_path
SARIF Report: $sarif_output
EOF
            
            # CSV
            echo "${APP_NAME},${build_type},${db_time},${analysis_time},${total_time},${alert_count},${error_count},${warning_count},${note_count},$(date -Iseconds)" >> "$CSV_FILE"
            
            # Logs
            cp codeql_db.log "$CODEQL_DIR/${APP_NAME}_${build_type}_codeql_db.log"
            cp codeql_analysis.log "$CODEQL_DIR/${APP_NAME}_${build_type}_codeql_analysis.log"
            
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] SUCCESS: CodeQL on $APP_NAME ($build_type) - ${alert_count} alerts in ${total_time}s" >> "$LOG_FILE"
            
            return 0
        else
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] FAILED: CodeQL analysis on $APP_NAME ($build_type)" >> "$LOG_FILE"
            cp codeql_analysis.log "$CODEQL_DIR/${APP_NAME}_${build_type}_codeql_analysis_FAILED.log" 2>/dev/null
            return 1
        fi
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] FAILED: CodeQL database creation on $APP_NAME ($build_type)" >> "$LOG_FILE"
        cp codeql_db.log "$CODEQL_DIR/${APP_NAME}_${build_type}_codeql_db_FAILED.log" 2>/dev/null
        return 1
    fi
}

try_codeql_build() {
    local java_version="$1"
    local compile_sdk="$2"
    local use_androidx="$3"
    local desc="$4"
    local module="$5"
    local build_type="$6"
    
    local minify="false"
    [ "$build_type" = "obfuscated" ] && minify="true"
    
    if run_codeql_analysis "$java_version" "$compile_sdk" "$use_androidx" "$minify" "$build_type" "$desc" "$module"; then
        return 0
    else
        return 1
    fi
}

JAVA11_HOME="$HOME/.sdkman/candidates/java/11.0.21-tem"

if [ ! -d "$JAVA11_HOME" ]; then
    JAVA11_HOME=$(find "$HOME/.sdkman/candidates/java" -maxdepth 1 -name "11.*" 2>/dev/null | head -1)
    [ -z "$JAVA11_HOME" ] && JAVA11_HOME=$(find /usr/lib/jvm -maxdepth 1 -name "*-11-*" 2>/dev/null | head -1)
fi

if [ ! -d "$JAVA11_HOME" ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] FAILED: Java 11 not found" >> "$LOG_FILE"
    exit 1
fi

MODULE=$(detect_module)
LIB_TYPE=$(detect_library_type)

OVERALL_SUCCESS=true

# Analyze normal build
if [ "$BUILD_TYPE" = "normal" ] || [ "$BUILD_TYPE" = "both" ]; then
    echo "Running CodeQL on NORMAL build..."
    
    SUCCESS=false
    if try_codeql_build "VERSION_1_8" "28" "false" "Java 8 + Support Library (SDK 28)" "$MODULE" "normal"; then
        SUCCESS=true
    elif try_codeql_build "VERSION_1_8" "33" "true" "Java 8 + AndroidX (SDK 33)" "$MODULE" "normal"; then
        SUCCESS=true
    elif try_codeql_build "VERSION_11" "33" "true" "Java 11 + AndroidX (SDK 33)" "$MODULE" "normal"; then
        SUCCESS=true
    fi
    
    if [ "$SUCCESS" = false ]; then
        OVERALL_SUCCESS=false
    fi
fi

# Analyze obfuscated build
if [ "$BUILD_TYPE" = "obfuscated" ] || [ "$BUILD_TYPE" = "both" ]; then
    echo "Running CodeQL on OBFUSCATED build..."
    
    SUCCESS=false
    if try_codeql_build "VERSION_1_8" "28" "false" "Java 8 + Support Library (SDK 28)" "$MODULE" "obfuscated"; then
        SUCCESS=true
    elif try_codeql_build "VERSION_1_8" "33" "true" "Java 8 + AndroidX (SDK 33)" "$MODULE" "obfuscated"; then
        SUCCESS=true
    elif try_codeql_build "VERSION_11" "33" "true" "Java 11 + AndroidX (SDK 33)" "$MODULE" "obfuscated"; then
        SUCCESS=true
    fi
    
    if [ "$SUCCESS" = false ]; then
        OVERALL_SUCCESS=false
    fi
fi

if [ "$OVERALL_SUCCESS" = true ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] COMPLETE: CodeQL analysis successful" >> "$LOG_FILE"
    echo "$APP_NAME: CODEQL SUCCESS"
    exit 0
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] COMPLETE: CodeQL analysis had failures" >> "$LOG_FILE"
    echo "$APP_NAME: CODEQL FAILED"
    exit 1
fi
