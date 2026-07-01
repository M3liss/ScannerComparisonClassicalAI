#!/usr/bin/env bash
#
# fetch_data.sh
#
# Downloads and extracts the app corpus + results archive from Zenodo.
#
# Requires: curl, jq, tar, sha256sum (or shasum on macOS)
#
# Usage:
#   ./fetch_data.sh                # fetch everything
#   ./fetch_data.sh apps           # fetch only fdroid_apps.tar.gz
#   ./fetch_data.sh obfuscated     # fetch only fdroid_apps_obfuscated.tar.gz
#   ./fetch_data.sh results        # fetch only results.tar.gz

set -euo pipefail

ZENODO_RECORD_ID="10.5281/zenodo.21098827"  
# ---------------------------------------------------------------------

API_URL="https://zenodo.org/api/records/${ZENODO_RECORD_ID}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${ZENODO_RECORD_ID}" == "10.5281/zenodo.21098827" ]]; then
  echo "ERROR: Set ZENODO_RECORD_ID at the top of this script to your Zenodo record ID." >&2
  echo "       (Find it in your record's URL: https://zenodo.org/records/<ID>)" >&2
  exit 1
fi

command -v jq >/dev/null 2>&1 || { echo "ERROR: jq is required (apt install jq / brew install jq)." >&2; exit 1; }

SHA_CMD="sha256sum"
command -v sha256sum >/dev/null 2>&1 || SHA_CMD="shasum -a 256"

echo "Fetching record metadata from Zenodo (record ${ZENODO_RECORD_ID})..."
METADATA=$(curl -sf "${API_URL}")

if [[ -z "${METADATA}" ]]; then
  echo "ERROR: Could not reach Zenodo or record not found." >&2
  exit 1
fi

# Map: logical name -> (filename fragment to match, extract-to directory)
declare -A TARGETS=(
  [apps]="fdroid_apps.tar.gz:${ROOT_DIR}/fdroid_apps"
  [obfuscated]="fdroid_apps_obfuscated.tar.gz:${ROOT_DIR}/fdroid_apps_obfuscated"
  [results]="results.tar.gz:${ROOT_DIR}/results"
)

REQUESTED="${1:-all}"
if [[ "${REQUESTED}" == "all" ]]; then
  KEYS=(apps obfuscated results)
else
  KEYS=("${REQUESTED}")
fi

for key in "${KEYS[@]}"; do
  if [[ -z "${TARGETS[$key]+x}" ]]; then
    echo "ERROR: Unknown target '${key}'. Valid options: apps, obfuscated, results, all" >&2
    exit 1
  fi

  FRAGMENT="${TARGETS[$key]%%:*}"
  DEST_DIR="${TARGETS[$key]#*:}"

  echo ""
  echo "== ${key} (${FRAGMENT}) =="

  # Look up download URL and checksum for this file from the Zenodo record metadata
  FILE_JSON=$(echo "${METADATA}" | jq -c --arg frag "${FRAGMENT}" \
    '.files[] | select(.key | contains($frag))')

  if [[ -z "${FILE_JSON}" ]]; then
    echo "WARNING: No file matching '${FRAGMENT}' found in this Zenodo record. Skipping." >&2
    continue
  fi

  DOWNLOAD_URL=$(echo "${FILE_JSON}" | jq -r '.links.self')
  EXPECTED_CHECKSUM=$(echo "${FILE_JSON}" | jq -r '.checksum' | sed 's/^md5://')
  FILENAME=$(echo "${FILE_JSON}" | jq -r '.key')

  TMP_FILE="${ROOT_DIR}/${FILENAME}"

  echo "Downloading ${FILENAME}..."
  curl -sf -L -o "${TMP_FILE}" "${DOWNLOAD_URL}"

  # Zenodo reports MD5 by default; verify with md5sum if available, else skip with a note
  if command -v md5sum >/dev/null 2>&1; then
    ACTUAL_CHECKSUM=$(md5sum "${TMP_FILE}" | awk '{print $1}')
    if [[ "${ACTUAL_CHECKSUM}" != "${EXPECTED_CHECKSUM}" ]]; then
      echo "ERROR: Checksum mismatch for ${FILENAME}!" >&2
      echo "  expected: ${EXPECTED_CHECKSUM}" >&2
      echo "  actual:   ${ACTUAL_CHECKSUM}" >&2
      exit 1
    fi
    echo "Checksum OK."
  else
    echo "NOTE: md5sum not available, skipping checksum verification." >&2
  fi

  mkdir -p "${DEST_DIR}"
  echo "Extracting to ${DEST_DIR}..."
  tar -xzf "${TMP_FILE}" -C "${DEST_DIR}" --strip-components=1 2>/dev/null \
    || tar -xzf "${TMP_FILE}" -C "${DEST_DIR}"
  rm "${TMP_FILE}"

  echo "Done: ${key} -> ${DEST_DIR}"
done

echo ""
echo "All requested data fetched."
