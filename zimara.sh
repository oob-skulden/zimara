#!/usr/bin/env bash
#
# Zimara v0.49.5 — Pre-Commit Security Audit (Static Sites + IaC/CI/CD)
# Published by Oob Skulden™
#
# The Complete Edition: Modern architecture with comprehensive check implementation
# and detailed inline violation display.
#
# Key features:
# - 53+ comprehensive security checks with detailed output
# - Inline snippet display with line numbers and context
# - Pattern matching visibility and remediation guidance
# - Real-time feedback as checks execute
# - Structured output (JSON/SARIF) for CI/CD
# - Baseline diffing for incremental adoption
# - Content-aware fingerprinting (never leaks secrets)
# - Injection-hardened .zimaraignore patterns

set -uo pipefail

readonly VERSION="0.49.5"
readonly SCRIPT_NAME="Zimara"

# Configuration flags
OUTPUT_FORMAT="text"
BASELINE_FILE=""
SAVE_BASELINE_FILE=""
SNIPPET_CONTEXT=3
SHOW_PATTERN=1
SHOW_HELP=false
VERBOSE=0
ONLY_OUTPUT=0
NON_INTERACTIVE=0

TARGET_PATH=""

# Color codes
readonly RED='\033[0;31m'
readonly YELLOW='\033[1;33m'
readonly GREEN='\033[0;32m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# Exit codes
readonly EXIT_SUCCESS=0
readonly EXIT_FINDINGS=1
readonly EXIT_ERROR=2

# Severity levels
readonly SEVERITY_CRITICAL="CRITICAL"
readonly SEVERITY_HIGH="HIGH"
readonly SEVERITY_MEDIUM="MEDIUM"
readonly SEVERITY_LOW="LOW"
readonly SEVERITY_INFO="INFO"

# Finding storage (parallel arrays for bash 3.2 compatibility)
declare -a FINDING_IDS=()
declare -a FINDING_SEVERITIES=()
declare -a FINDING_MESSAGES=()
declare -a FINDING_FILES=()
declare -a FINDING_LINES=()
declare -a FINDING_SNIPPETS=()
declare -a FINDING_PATTERNS=()
declare -a FINDING_ACTIONS=()
declare -a FINDING_FINGERPRINTS=()

# Counters
FINDING_COUNT=0
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0

# Generator detection
GENERATOR="generic"
OUTPUT_DIR=""

# Temp file tracking
TMP_FILES=()

cleanup() {
  local f
  for f in "${TMP_FILES[@]:-}"; do
    [[ -n "${f}" && -f "${f}" ]] && rm -f -- "${f}" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM

tmpfile() {
  local prefix="${1:-zimara}"
  local suffix="${2:-}"
  local f=""

  f="$(mktemp -t "${prefix}.XXXXXX${suffix}" 2>/dev/null || mktemp "/tmp/${prefix}.XXXXXX${suffix}")" || {
    echo "FATAL: Cannot create secure temp file" >&2
    exit 99
  }

  if [[ ! -f "$f" || -L "$f" || ! -O "$f" ]]; then
    rm -f -- "$f" 2>/dev/null || true
    echo "FATAL: Temp file safety/ownership violation" >&2
    exit 99
  fi

  TMP_FILES+=("$f")
  echo "$f"
}

# ============================================
# Output Functions
# ============================================

print_color() {
    local color=$1
    shift
    if [[ "$OUTPUT_FORMAT" == "text" ]]; then
        echo -e "${color}$*${NC}"
    fi
}

error() { print_color "$RED" "ERROR: $*" >&2; }
warn() { print_color "$YELLOW" "WARNING: $*" >&2; }
info() { print_color "$BLUE" "$*"; }
success() { print_color "$GREEN" "$*"; }

check_header() {
    local check_num=$1 check_name=$2
    if [[ "$OUTPUT_FORMAT" == "text" ]]; then
        echo ""
        print_color "$PURPLE" "────────────────────────────────────────────────────────────────────"
        print_color "$PURPLE" "CHECK ${check_num}: ${check_name}"
        print_color "$PURPLE" "────────────────────────────────────────────────────────────────────"
    fi
}

check_pass() {
    local message=$1
    [[ "$OUTPUT_FORMAT" == "text" ]] && success "✓ ${message}"
}

check_info() {
    local message=$1
    [[ "$OUTPUT_FORMAT" == "text" ]] && info "ℹ ${message}"
}

# ============================================
# Help and Argument Parsing
# ============================================

show_help() {
    cat <<EOF
$SCRIPT_NAME v$VERSION — Pre-Commit Security Audit for Static Sites
Published by Oob Skulden™

USAGE:
    $0 [PATH] [OPTIONS]

ARGUMENTS:
    PATH                    Directory to scan (default: current directory)

OPTIONS:
    --format FORMAT         Output format: text, json, sarif (default: text)
    --baseline FILE         Compare against baseline, show only new findings
    --save-baseline FILE    Save current findings as baseline for future runs
    --snippet-context N     Lines of context around findings (default: 3)
    --no-pattern            Don't show regex patterns in output
    -v, --verbose           Show additional check details
    -o, --only-output       Scan only build output (skip source)
    -n, --non-interactive   Non-interactive mode (CI-safe)
    --help                  Show this help message

EXAMPLES:
    # Standard text output with real-time feedback
    $0

    # Scan specific directory
    $0 ~/projects/mysite

    # JSON output for CI/CD integration
    $0 --format json

    # SARIF output for GitHub Code Scanning
    $0 --format sarif > results.sarif

    # Baseline workflow (incremental adoption)
    $0 --save-baseline .zimara-baseline.json
    $0 --baseline .zimara-baseline.json

    # Scan only build output
    $0 --only-output

INSTALLATION:
    # As pre-commit hook
    ln -s ../../zimara.sh .git/hooks/pre-commit
    chmod +x zimara.sh

    # Manual execution
    ./zimara.sh

IGNORE PATTERNS:
    Create .zimaraignore to exclude files from scanning.
    Supports wildcards and directory patterns.

SECURITY FEATURES:
    - 53+ comprehensive checks across multiple attack surfaces
    - Real-time feedback with inline violation display
    - Pattern matching visibility and remediation guidance
    - Content-aware fingerprinting (secrets never leaked)
    - Baseline diffing for incremental validation
    - Injection-hardened ignore patterns
    - Multiple output formats (text, JSON, SARIF)

For more information, see:
    README.md, CHECKS.md, INTEGRATION.md, SECURITY.md

EOF
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --format)
                OUTPUT_FORMAT="$2"
                if [[ ! "$OUTPUT_FORMAT" =~ ^(text|json|sarif)$ ]]; then
                    error "Invalid format: $OUTPUT_FORMAT"
                    exit $EXIT_ERROR
                fi
                shift 2
                ;;
            --baseline)
                BASELINE_FILE="$2"
                [[ ! -f "$BASELINE_FILE" ]] && error "Baseline file not found: $BASELINE_FILE" && exit $EXIT_ERROR
                shift 2
                ;;
            --save-baseline)
                SAVE_BASELINE_FILE="$2"
                shift 2
                ;;
            --snippet-context)
                SNIPPET_CONTEXT="$2"
                [[ ! "$SNIPPET_CONTEXT" =~ ^[0-9]+$ ]] && error "snippet-context must be a number" && exit $EXIT_ERROR
                shift 2
                ;;
            --no-pattern)
                SHOW_PATTERN=0
                shift
                ;;
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            -o|--only-output)
                ONLY_OUTPUT=1
                shift
                ;;
            -n|--non-interactive)
                NON_INTERACTIVE=1
                shift
                ;;
            --help)
                SHOW_HELP=true
                shift
                ;;
            --)
                shift
                while [[ $# -gt 0 ]]; do
                    if [[ -z "$TARGET_PATH" ]]; then
                        TARGET_PATH="$1"
                    else
                        error "Unexpected extra argument: $1"
                        exit $EXIT_ERROR
                    fi
                    shift
                done
                break
                ;;
            *)
                if [[ "$1" == -* ]]; then
                    error "Unknown option: $1"
                    show_help
                    exit $EXIT_ERROR
                fi
                if [[ -z "$TARGET_PATH" ]]; then
                    TARGET_PATH="$1"
                    shift
                else
                    error "Unexpected extra argument: $1"
                    exit $EXIT_ERROR
                fi
                ;;
        esac
    done
}

# ============================================
# Target Directory Handling
# ============================================

resolve_target_dir() {
    local input="${1:-.}"
    input="${input/#\~/$HOME}"

    if [[ ! -d "$input" ]]; then
        error "Target directory does not exist: $input"
        exit $EXIT_ERROR
    fi

    (cd "$input" && pwd -P)
}

# ============================================
# Fingerprinting and Sanitization
# ============================================

generate_fingerprint() {
    local check_id=$1 file=$2 line=$3
    local fingerprint_input="${check_id}:${file}:${line}"
    
    if command -v sha256sum >/dev/null 2>&1; then
        echo -n "$fingerprint_input" | sha256sum | awk '{print $1}'
    elif command -v md5sum >/dev/null 2>&1; then
        echo -n "$fingerprint_input" | md5sum | awk '{print $1}'
    else
        echo -n "$fingerprint_input" | od -A n -t x1 | tr -d ' \n'
    fi
}

sanitize_snippet() {
    local snippet=$1
    # Redact potential secrets while preserving structure
    snippet=$(echo "$snippet" | sed -E 's/[A-Za-z0-9_-]{20,}/[REDACTED]/g')
    snippet=$(echo "$snippet" | sed -E 's/ghp_[A-Za-z0-9]{36}/[GITHUB_TOKEN]/g')
    snippet=$(echo "$snippet" | sed -E 's/gho_[A-Za-z0-9]{36}/[GITHUB_OAUTH]/g')
    snippet=$(echo "$snippet" | sed -E 's/AKIA[A-Z0-9]{16}/[AWS_KEY]/g')
    snippet=$(echo "$snippet" | sed -E 's/sk-[A-Za-z0-9]{48}/[OPENAI_KEY]/g')
    echo "$snippet"
}

# ============================================
# Snippet Extraction
# ============================================

get_snippet_context() {
    local file=$1 line_num=$2 context=${3:-$SNIPPET_CONTEXT}
    
    [[ ! -f "$file" || ! -r "$file" ]] && echo "" && return
    
    # Check if file appears to be binary
    if file "$file" 2>/dev/null | grep -qE 'executable|binary'; then
        echo "[BINARY FILE]"
        return
    fi
    
    local start=$((line_num - context)) end=$((line_num + context))
    [[ $start -lt 1 ]] && start=1
    
    local output="" current_line=$start
    
    while IFS= read -r line && [[ $current_line -le $end ]]; do
        local display_line="$line"
        if [[ "${#line}" -gt 120 ]]; then
            display_line="${line:0:120}..."
        fi
        
        if [[ $current_line -eq $line_num ]]; then
            output="${output}  >> $(printf "%4d" $current_line) | ${display_line}"$'\n'
        else
            output="${output}     $(printf "%4d" $current_line) | ${display_line}"$'\n'
        fi
        ((current_line++))
    done < <(sed -n "${start},${end}p" "$file" 2>/dev/null)
    
    echo "$output"
}

# ============================================
# Finding Management
# ============================================

add_finding() {
    local severity=$1 message=$2 file=$3 line=${4:-0} pattern=${5:-""} action=${6:-""} check_id=${7:-"UNKNOWN"}
    
    local safe_message snippet=""
    
    if [[ $line -gt 0 && -f "$file" ]]; then
        snippet=$(get_snippet_context "$file" "$line")
        safe_message="${message} at ${file}:${line}"
    else
        safe_message="${message} in ${file}"
    fi
    
    local sanitized_snippet=""
    if [[ -n "$snippet" ]]; then
        sanitized_snippet=$(sanitize_snippet "$snippet")
    fi
    
    local fingerprint
    fingerprint=$(generate_fingerprint "$check_id" "$file" "$line")
    
    FINDING_IDS+=("$check_id")
    FINDING_SEVERITIES+=("$severity")
    FINDING_MESSAGES+=("$safe_message")
    FINDING_FILES+=("$file")
    FINDING_LINES+=("$line")
    FINDING_SNIPPETS+=("$sanitized_snippet")
    FINDING_PATTERNS+=("$pattern")
    FINDING_ACTIONS+=("$action")
    FINDING_FINGERPRINTS+=("$fingerprint")
    
    ((++FINDING_COUNT))
    case $severity in
        "$SEVERITY_CRITICAL") ((++CRITICAL_COUNT)) ;;
        "$SEVERITY_HIGH") ((++HIGH_COUNT)) ;;
        "$SEVERITY_MEDIUM") ((++MEDIUM_COUNT)) ;;
        "$SEVERITY_LOW") ((++LOW_COUNT)) ;;
    esac
    
    # Real-time detailed feedback
    if [[ "$OUTPUT_FORMAT" == "text" ]]; then
        echo ""
        case $severity in
            "$SEVERITY_CRITICAL") print_color "$RED" "  ✗ [CRITICAL] ${message} at ${file}:${line}" ;;
            "$SEVERITY_HIGH") print_color "$RED" "  ✗ [HIGH] ${message} at ${file}:${line}" ;;
            "$SEVERITY_MEDIUM") print_color "$YELLOW" "  ⚠ [MEDIUM] ${message} at ${file}:${line}" ;;
            "$SEVERITY_LOW") print_color "$BLUE" "  ℹ [LOW] ${message} at ${file}:${line}" ;;
        esac
        
        if [[ -n "$sanitized_snippet" && "$sanitized_snippet" != "[BINARY FILE]" ]]; then
            print_color "$CYAN" "  ────────────────────────────────────────────────────────────────"
            echo -e "$sanitized_snippet"
            print_color "$CYAN" "  ────────────────────────────────────────────────────────────────"
        fi
        
        if [[ "$SHOW_PATTERN" -eq 1 && -n "$pattern" ]]; then
            echo "  Pattern: ${pattern}"
        fi
        
        if [[ -n "$action" ]]; then
            echo ""
            echo "  ACTION: ${action}"
        fi
    fi
}

# ============================================
# .zimaraignore Support
# ============================================

MAX_IGNORE_PATTERNS=100
MAX_PATTERN_LENGTH=200
SAFE_PATTERN_REGEX='^[a-zA-Z0-9._/*-]+$'

IGNORE_PATTERNS=()

validate_ignore_pattern() {
  local pattern="$1"
  
  [[ "${#pattern}" -gt "$MAX_PATTERN_LENGTH" ]] && warn "Pattern exceeds ${MAX_PATTERN_LENGTH} chars: ${pattern:0:50}..." && return 1
  [[ ! "$pattern" =~ $SAFE_PATTERN_REGEX ]] && warn "Invalid pattern (only a-z A-Z 0-9 . / - _ * allowed): ${pattern}" && return 1
  [[ "$pattern" =~ ^- ]] && warn "Pattern cannot start with '-': ${pattern}" && return 1
  [[ "$pattern" =~ \.\. ]] && warn "Path traversal not allowed (..): ${pattern}" && return 1
  [[ "$pattern" =~ ^/ ]] && warn "Absolute paths not allowed: ${pattern}" && return 1
  
  case "$pattern" in
    "*"|"*/*"|"*.*"|".")
      warn "Very broad pattern may disable important checks: ${pattern}"
      ;;
  esac
  
  return 0
}

load_ignore_patterns() {
    local ignore_file=".zimaraignore"
    IGNORE_PATTERNS=()
    [[ ! -f "$ignore_file" ]] && return 0
    
    local pattern_count=0
    
    while IFS= read -r line || [[ -n "$line" ]]; do
        local pattern
        pattern="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [[ -z "$pattern" || "$pattern" =~ ^# ]] && continue
        [[ $pattern_count -ge $MAX_IGNORE_PATTERNS ]] && warn "Maximum ${MAX_IGNORE_PATTERNS} patterns reached" && break
        
        if validate_ignore_pattern "$pattern"; then
            IGNORE_PATTERNS+=("$pattern")
            ((++pattern_count))
        fi
    done < "$ignore_file"
    
    [[ "$OUTPUT_FORMAT" == "text" && ${#IGNORE_PATTERNS[@]} -gt 0 ]] && info "Loaded ${#IGNORE_PATTERNS[@]} ignore pattern(s) from .zimaraignore"
}

should_ignore_file() {
    local file=$1
    [[ ${#IGNORE_PATTERNS[@]} -eq 0 ]] && return 1
    
    # Normalize file path - remove leading ./
    local normalized_file="${file#./}"
    
    local pattern
    for pattern in "${IGNORE_PATTERNS[@]}"; do
        # Convert glob pattern to regex
        local grep_pattern
        grep_pattern=$(echo "$pattern" | sed 's/\./\\./g' | sed 's/\*/.*/g')
        
        # Try exact match first (for paths like "dir/file.txt")
        if echo "$normalized_file" | grep -qE "^${grep_pattern}$" 2>/dev/null; then
            return 0
        fi
        
        # Try basename match (for simple filenames like "config.txt")
        local basename="${normalized_file##*/}"
        if echo "$basename" | grep -qE "^${grep_pattern}$" 2>/dev/null; then
            return 0
        fi
        
        # Try path contains match (for patterns like "*.txt")
        if echo "$normalized_file" | grep -qE "${grep_pattern}" 2>/dev/null; then
            return 0
        fi
    done
    
    return 1
}

# ============================================
# Baseline Management
# ============================================

load_baseline() {
    local baseline_file=$1
    [[ ! -f "$baseline_file" ]] && error "Baseline not found: $baseline_file" && return 1
    cat "$baseline_file"
}

is_in_baseline() {
    local fingerprint=$1 baseline=$2
    echo "$baseline" | jq -e ".findings[] | select(.fingerprint == \"$fingerprint\")" >/dev/null 2>&1
}

filter_baseline_findings() {
    [[ "$OUTPUT_FORMAT" == "text" ]] && info "Filtering findings against baseline..."
    
    local baseline
    baseline=$(load_baseline "$BASELINE_FILE")
    
    local -a new_finding_ids=() new_finding_severities=() new_finding_messages=()
    local -a new_finding_files=() new_finding_lines=() new_finding_snippets=()
    local -a new_finding_patterns=() new_finding_actions=() new_finding_fingerprints=()
    local new_count=0
    
    for i in "${!FINDING_FINGERPRINTS[@]}"; do
        local fingerprint="${FINDING_FINGERPRINTS[$i]}"
        if ! is_in_baseline "$fingerprint" "$baseline"; then
            new_finding_ids+=("${FINDING_IDS[$i]}")
            new_finding_severities+=("${FINDING_SEVERITIES[$i]}")
            new_finding_messages+=("${FINDING_MESSAGES[$i]}")
            new_finding_files+=("${FINDING_FILES[$i]}")
            new_finding_lines+=("${FINDING_LINES[$i]}")
            new_finding_snippets+=("${FINDING_SNIPPETS[$i]}")
            new_finding_patterns+=("${FINDING_PATTERNS[$i]}")
            new_finding_actions+=("${FINDING_ACTIONS[$i]}")
            new_finding_fingerprints+=("${FINDING_FINGERPRINTS[$i]}")
            ((++new_count))
        fi
    done
    
    FINDING_IDS=("${new_finding_ids[@]}")
    FINDING_SEVERITIES=("${new_finding_severities[@]}")
    FINDING_MESSAGES=("${new_finding_messages[@]}")
    FINDING_FILES=("${new_finding_files[@]}")
    FINDING_LINES=("${new_finding_lines[@]}")
    FINDING_SNIPPETS=("${new_finding_snippets[@]}")
    FINDING_PATTERNS=("${new_finding_patterns[@]}")
    FINDING_ACTIONS=("${new_finding_actions[@]}")
    FINDING_FINGERPRINTS=("${new_finding_fingerprints[@]}")
    FINDING_COUNT=$new_count
    
    CRITICAL_COUNT=0 HIGH_COUNT=0 MEDIUM_COUNT=0 LOW_COUNT=0
    for severity in "${FINDING_SEVERITIES[@]}"; do
        case $severity in
            "$SEVERITY_CRITICAL") ((++CRITICAL_COUNT)) ;;
            "$SEVERITY_HIGH") ((++HIGH_COUNT)) ;;
            "$SEVERITY_MEDIUM") ((++MEDIUM_COUNT)) ;;
            "$SEVERITY_LOW") ((++LOW_COUNT)) ;;
        esac
    done
    
    [[ "$OUTPUT_FORMAT" == "text" ]] && info "Found ${new_count} new finding(s) not in baseline"
}

# ============================================
# Generator Detection
# ============================================

detect_generator() {
  if [[ -f "hugo.toml" || -f "config.toml" || -f "config.yaml" || -f "config.yml" ]]; then
    GENERATOR="hugo"; OUTPUT_DIR="public"
  elif [[ -f "_config.yml" || -f "_config.yaml" ]]; then
    GENERATOR="jekyll"; OUTPUT_DIR="_site"
  elif [[ -f "astro.config.mjs" || -f "astro.config.ts" ]]; then
    GENERATOR="astro"; OUTPUT_DIR="dist"
  elif [[ -f "eleventy.config.js" || -f ".eleventy.js" ]]; then
    GENERATOR="eleventy"; OUTPUT_DIR="_site"
  elif [[ -f "next.config.js" || -f "next.config.mjs" || -f "next.config.ts" ]]; then
    GENERATOR="next"; OUTPUT_DIR="out"
  else
    GENERATOR="generic"
    if [[ -d "public" ]]; then OUTPUT_DIR="public"
    elif [[ -d "dist" ]]; then OUTPUT_DIR="dist"
    elif [[ -d "_site" ]]; then OUTPUT_DIR="_site"
    elif [[ -d "out" ]]; then OUTPUT_DIR="out"
    else OUTPUT_DIR="" ; fi
  fi
}

# ============================================
# Security Checks (1-53)
# ============================================

check_01_repo_structure() {
    check_header "01" "Repository Structure"
    
    if [[ -d ".git" ]]; then
        check_pass "Git repository detected"
    else
        add_finding "$SEVERITY_LOW" "No .git directory found" "." "0" "" "Consider initializing git repository for version control" "CHECK_01"
    fi
}

check_02_gitignore() {
    check_header "02" ".gitignore Hygiene"
    
    if [[ -f ".gitignore" ]]; then
        check_pass ".gitignore present"
    else
        add_finding "$SEVERITY_LOW" "Missing .gitignore" "." "0" "" "Add .gitignore to prevent committing secrets/build artifacts" "CHECK_02"
    fi
}

check_03_private_keys() {
    check_header "03" "Private Keys (Hard Stop)"
    
    [[ "$ONLY_OUTPUT" -eq 1 ]] && check_info "Skipping source scan (--only-output)" && return 0
    
    local pattern='-----BEGIN.*PRIVATE KEY-----'
    local found=0
    
    local files
    files=$(find . \
        \( -path "./.git" -o -path "./node_modules" -o -path "./vendor" \) -prune -o \
        -type f -print 2>/dev/null)
    
    while IFS= read -r file ; do
        [[ -z "$file" || ! -f "$file" ]] && continue
        should_ignore_file "$file" && continue
        
        # Skip binary files
        file "$file" 2>/dev/null | grep -q text || continue
        
        while IFS=: read -r line_num match; do
            [[ -z "$line_num" ]] && continue
            add_finding "$SEVERITY_CRITICAL" "Private key detected" "$file" "$line_num" "$pattern" "Remove immediately and rotate credentials. Private keys should never be committed to source control." "CHECK_03"
            found=1
        done < <(grep -n -E -- "$pattern" "$file" 2>/dev/null || true)
    done <<< "$files"
    
    [[ $found -eq 0 ]] && check_pass "No private key blocks found"
}

check_04_secret_patterns() {
    check_header "04" "Secrets Pattern Scan"
    
    [[ "$ONLY_OUTPUT" -eq 1 ]] && check_info "Skipping source scan (--only-output)" && return 0
    
    local -a patterns=(
        'AKIA[A-Z0-9]{16}'
        'ghp_[A-Za-z0-9]{36}'
        'gho_[A-Za-z0-9]{36}'
        'glpat-[0-9A-Za-z\-_]{20,}'
        'xox[baprs]-[0-9A-Za-z-]{10,}'
        'sk-[A-Za-z0-9]{48}'
    )
    
    local found=0
    local files
    files=$(find . \
        \( -path "./.git" -o -path "./node_modules" -o -path "./vendor" \) -prune -o \
        -type f ! -name "*.min.js" ! -name "*.map" ! -name "*.sh" -print 2>/dev/null)
    
    while IFS= read -r file ; do
        [[ -z "$file" || ! -f "$file" ]] && continue
        should_ignore_file "$file" && continue
        
        # Skip binary files
        file "$file" 2>/dev/null | grep -q text || continue
        
        for pattern in "${patterns[@]}"; do
            while IFS=: read -r line_num match; do
                [[ -z "$line_num" ]] && continue
                add_finding "$SEVERITY_HIGH" "Possible secret pattern detected" "$file" "$line_num" "$pattern" "Remove secret, rotate credentials, use environment variables or secret manager" "CHECK_04"
                found=1
            done < <(grep -n -E "$pattern" "$file" 2>/dev/null || true)
        done
    done <<< "$files"
    
    [[ $found -eq 0 ]] && check_pass "No obvious secret patterns found"
}

check_05_backup_artifacts() {
    check_header "05" "Backup/Temp Artifacts"
    
    [[ "$ONLY_OUTPUT" -eq 1 ]] && check_info "Skipping source scan (--only-output)" && return 0
    
    local hits found=0
    hits="$(find . \
        \( -path "./.git" -o -path "./node_modules" -o -path "./vendor" \) -prune -o \
        -type f \( -name "*.bak" -o -name "*.old" -o -name "*.backup" -o -name "*.tmp" -o -name "*~" \) \
        -print 2>/dev/null | head -n 10 || true)"

    if [[ -n "${hits}" ]]; then
        while IFS= read -r file ; do
            [[ -z "$file" ]] && continue
            add_finding "$SEVERITY_MEDIUM" "Backup/temp artifact present" "$file" "0" "\.(bak|old|backup|tmp)|~$" "Delete or add to .gitignore. Backup files may contain sensitive data." "CHECK_05"
            found=1
        done <<< "$hits"
    fi
    
    [[ $found -eq 0 ]] && check_pass "No backup/temp artifacts found"
}

check_06_dotenv_files() {
    check_header "06" "Dotenv Files"
    
    local hits found=0
    hits="$(find . \
        \( -path "./.git" -o -path "./node_modules" -o -path "./vendor" \) -prune -o \
        -type f \( -name ".env" -o -name ".env.*" -o -name "*.env" \) -print 2>/dev/null | head -n 10 || true)"

    if [[ -n "${hits}" ]]; then
        while IFS= read -r file ; do
            [[ -z "$file" ]] && continue
            add_finding "$SEVERITY_MEDIUM" ".env-style file detected" "$file" "0" "\.env(\.|$)" "Ensure .env files are not committed and are in .gitignore" "CHECK_06"
            found=1
        done <<< "$hits"
    fi
    
    [[ $found -eq 0 ]] && check_pass "No .env files detected"
}

check_07_output_exposure() {
    check_header "07" "Build Output Exposure"
    
    [[ -z "${OUTPUT_DIR}" || ! -d "${OUTPUT_DIR}" ]] && check_info "No build output directory detected" && return 0

    local found=0
    
    if [[ -d "${OUTPUT_DIR}/.git" ]]; then
        add_finding "$SEVERITY_CRITICAL" "Output contains .git directory" "${OUTPUT_DIR}/.git" "0" "" "Ensure build output does not include .git. Clean output directory and rebuild." "CHECK_07"
        found=1
    fi

    local pattern='-----BEGIN.*PRIVATE KEY-----'
    local tmpf
    tmpf="$(tmpfile output-keys)"
    
    find "${OUTPUT_DIR}" -type f -maxdepth 6 -print0 2>/dev/null \
        | xargs -0 grep -l -E "$pattern" 2>/dev/null > "$tmpf" || true

    if [[ -s "$tmpf" ]]; then
        while IFS= read -r file ; do
            add_finding "$SEVERITY_CRITICAL" "Output contains private key material" "$file" "0" "$pattern" "Remove private keys from build output immediately" "CHECK_07"
            found=1
        done < <(head -5 "$tmpf")
    fi
    
    [[ $found -eq 0 ]] && check_pass "No sensitive files in build output"
}

check_08_mixed_content() {
    check_header "08" "Mixed Content (Output)"
    
    [[ -z "${OUTPUT_DIR}" || ! -d "${OUTPUT_DIR}" ]] && check_info "No build output directory detected" && return 0

    local pattern='(href="http://|src="http://|url\("http://)'
    local tmpf found=0
    tmpf="$(tmpfile mixed-content)"
    
    grep -RIn --exclude="*.map" -E "$pattern" "${OUTPUT_DIR}" 2>/dev/null > "$tmpf" || true
    
    if [[ -s "$tmpf" ]]; then
        local count=0
        while IFS=: read -r file line_num match && [[ $count -lt 5 ]]; do
            add_finding "$SEVERITY_MEDIUM" "Mixed content reference found" "$file" "$line_num" "$pattern" "Use https:// resources to avoid downgrade attacks and browser blocking" "CHECK_08"
            found=1
            ((++count))
        done < "$tmpf"
    fi
    
    [[ $found -eq 0 ]] && check_pass "No mixed content references found"
}

check_09_netlify_config() {
    check_header "09" "Netlify Config Presence"
    
    if [[ -f "netlify.toml" ]]; then
        check_pass "netlify.toml detected"
    else
        check_info "netlify.toml not found (ok if not using Netlify)"
    fi
}

check_10_netlify_headers() {
    check_header "10" "Security Headers (Netlify) — Basic"
    
    [[ ! -f "netlify.toml" ]] && check_info "netlify.toml not found" && return 0

    local hsts xcto found=0
    hsts="$(grep -nE 'Strict-Transport-Security' netlify.toml 2>/dev/null | head -n 1 || true)"
    xcto="$(grep -nE 'X-Content-Type-Options' netlify.toml 2>/dev/null | head -n 1 || true)"

    if [[ -z "${hsts}" ]]; then
        add_finding "$SEVERITY_LOW" "Missing HSTS header" "netlify.toml" "0" "Strict-Transport-Security" "Add HSTS header to prevent protocol downgrade attacks" "CHECK_10"
        found=1
    fi

    if [[ -z "${xcto}" ]]; then
        add_finding "$SEVERITY_LOW" "Missing X-Content-Type-Options header" "netlify.toml" "0" "X-Content-Type-Options" "Add X-Content-Type-Options: nosniff to prevent MIME sniffing" "CHECK_10"
        found=1
    fi
    
    [[ $found -eq 0 ]] && check_pass "Basic security headers present"
}

check_11_github_actions() {
    check_header "11" "GitHub Actions Directory"
    
    if [[ -d ".github" ]]; then
        check_pass ".github directory present"
    else
        check_info ".github directory not found"
    fi
}

check_12_gitleaks() {
    check_header "12" "Gitleaks Integration"
    
    [[ "$ONLY_OUTPUT" -eq 1 ]] && check_info "Skipping source scan (--only-output)" && return 0
    
    if ! command -v gitleaks >/dev/null 2>&1; then
        check_info "gitleaks not installed (optional but recommended)"
        return 0
    fi
    
    [[ ! -d ".git" ]] && check_info "Skipping gitleaks (not a git repository)" && return 0
    
    local tmpf found=0
    tmpf="$(tmpfile gitleaks-report .json)"
    
    gitleaks detect --source . --report-format json --report-path "$tmpf" >/dev/null 2>&1 || true
    
    if [[ -f "$tmpf" && -s "$tmpf" ]]; then
        local count
        count=$(jq '. | length' "$tmpf" 2>/dev/null || echo "0")
        if [[ "$count" -gt 0 ]]; then
            add_finding "$SEVERITY_HIGH" "Gitleaks detected ${count} potential secret(s)" "." "0" "" "Review gitleaks report: ${tmpf}. Remove secrets and rotate credentials." "CHECK_12"
            found=1
        fi
    fi
    
    [[ $found -eq 0 ]] && check_pass "Gitleaks found no issues"
}

check_13_detect_secrets() {
    check_header "13" "detect-secrets Integration"
    
    [[ "$ONLY_OUTPUT" -eq 1 ]] && check_info "Skipping source scan (--only-output)" && return 0
    
    if ! command -v detect-secrets >/dev/null 2>&1; then
        check_info "detect-secrets not installed (optional)"
        return 0
    fi
    
    local tmpf found=0
    tmpf="$(tmpfile detect-secrets-report .json)"
    
    detect-secrets scan --all-files 2>/dev/null > "$tmpf" || true
    
    if [[ -f "$tmpf" && -s "$tmpf" ]]; then
        local count
        count=$(jq '.results | to_entries | length' "$tmpf" 2>/dev/null || echo "0")
        if [[ "$count" -gt 0 ]]; then
            add_finding "$SEVERITY_MEDIUM" "detect-secrets found ${count} potential secret(s)" "." "0" "" "Run: detect-secrets scan --all-files -v" "CHECK_13"
            found=1
        fi
    fi
    
    [[ $found -eq 0 ]] && check_pass "detect-secrets found no issues"
}

check_14_npm_audit() {
    check_header "14" "npm audit (Dependency Vulnerabilities)"
    
    [[ ! -f "package.json" ]] && check_info "package.json not found" && return 0
    
    if ! command -v npm >/dev/null 2>&1; then
        check_info "npm not installed"
        return 0
    fi
    
    local tmpf found=0
    tmpf="$(tmpfile npm-audit .json)"
    
    npm audit --json 2>/dev/null > "$tmpf" || true
    
    if [[ -f "$tmpf" && -s "$tmpf" ]]; then
        local high critical
        high=$(jq '.metadata.vulnerabilities.high // 0' "$tmpf" 2>/dev/null || echo "0")
        critical=$(jq '.metadata.vulnerabilities.critical // 0' "$tmpf" 2>/dev/null || echo "0")
        
        if [[ "$critical" -gt 0 ]]; then
            add_finding "$SEVERITY_CRITICAL" "npm audit found ${critical} critical vulnerabilities" "package.json" "0" "" "Run: npm audit. Update dependencies or apply fixes." "CHECK_14"
            found=1
        elif [[ "$high" -gt 0 ]]; then
            add_finding "$SEVERITY_HIGH" "npm audit found ${high} high vulnerabilities" "package.json" "0" "" "Run: npm audit. Update dependencies or apply fixes." "CHECK_14"
            found=1
        fi
    fi
    
    [[ $found -eq 0 ]] && check_pass "npm audit found no high/critical vulnerabilities"
}

check_15_worktree_clean() {
    check_header "15" "Working Tree Cleanliness"
    
    [[ ! -d ".git" ]] && check_info "Not a git repository" && return 0
    
    if ! command -v git >/dev/null 2>&1; then
        check_info "git not available"
        return 0
    fi
    
    local st
    st="$(git status --porcelain 2>/dev/null || true)"
    if [[ -n "${st}" ]]; then
        check_info "Uncommitted changes detected (ok for pre-commit checks)"
    else
        check_pass "Working tree clean"
    fi
}

check_16_risky_debug_output() {
    check_header "16" "Risky Debug Artifacts (Output)"
    
    [[ -z "${OUTPUT_DIR}" || ! -d "${OUTPUT_DIR}" ]] && check_info "No build output directory detected" && return 0
    
    local hits found=0
    hits="$(find "${OUTPUT_DIR}" -type f \( -name "debug.log" -o -name "phpinfo.php" -o -name "*.sql" \) -print 2>/dev/null | head -n 10 || true)"
    
    if [[ -n "${hits}" ]]; then
        while IFS= read -r file ; do
            [[ -z "$file" ]] && continue
            add_finding "$SEVERITY_HIGH" "Risky debug artifact in output" "$file" "0" "(debug\.log|phpinfo\.php|\.sql$)" "Remove debug artifacts. Ensure build pipeline excludes them." "CHECK_16"
            found=1
        done <<< "$hits"
    fi
    
    [[ $found -eq 0 ]] && check_pass "No risky debug artifacts in output"
}

check_17_git_history_sensitive() {
    check_header "17" "Git History — Sensitive Extensions"
    
    [[ "$ONLY_OUTPUT" -eq 1 ]] && check_info "Skipping source scan (--only-output)" && return 0
    [[ ! -d ".git" ]] && check_info "No git repository" && return 0

    if ! command -v git >/dev/null 2>&1; then
        check_info "git not available"
        return 0
    fi

    local count tmpf found=0
    tmpf="$(tmpfile git-history-check)"
    
    git log --all --oneline --name-only 2>/dev/null \
        | grep -E '\.(env|key|pem|p12|pfx|backup|bak)$' 2>/dev/null \
        > "${tmpf}" || true
    
    count="$(wc -l < "${tmpf}" 2>/dev/null | tr -d ' ')"

    if [[ "${count:-0}" -gt 0 ]]; then
        add_finding "$SEVERITY_MEDIUM" "Found ${count} sensitive file reference(s) in git history" ".git" "0" "\.(env|key|pem|p12|pfx|backup|bak)$" "Secrets may remain in history. Use git filter-repo/BFG to purge, then rotate secrets." "CHECK_17"
        found=1
    fi
    
    [[ $found -eq 0 ]] && check_pass "No sensitive files in git history"
}

check_18_git_remote_http() {
    check_header "18" "Git Remote URL Hygiene"
    
    [[ ! -d ".git" ]] && check_info "Not a git repository" && return 0
    
    if ! command -v git >/dev/null 2>&1; then
        check_info "git not available"
        return 0
    fi
    
    local rem found=0
    rem="$(git remote -v 2>/dev/null || true)"
    
    if echo "$rem" | grep -qiE 'http://'; then
        while IFS= read -r line; do
            if echo "$line" | grep -qiE 'http://'; then
                add_finding "$SEVERITY_MEDIUM" "Git remote uses http:// (insecure)" ".git/config" "0" "http://" "Switch to https:// or ssh (git@...) remotes" "CHECK_18"
                found=1
                break
            fi
        done <<< "$rem"
    fi
    
    [[ $found -eq 0 ]] && check_pass "No http:// git remotes detected"
}

check_19_sensitive_filenames() {
    check_header "19" "Known Sensitive Filenames"
    
    [[ "$ONLY_OUTPUT" -eq 1 ]] && check_info "Skipping source scan (--only-output)" && return 0

    local hits found=0
    hits="$(find . \
        \( -path "./.git" -o -path "./node_modules" -o -path "./vendor" \) -prune -o \
        -type f \( -name "id_rsa" -o -name "id_ed25519" -o -name "*.pem" -o -name "*.p12" -o -name "*.pfx" \) \
        -print 2>/dev/null | head -n 10 || true)"

    if [[ -n "${hits}" ]]; then
        while IFS= read -r file ; do
            [[ -z "$file" ]] && continue
            add_finding "$SEVERITY_HIGH" "Sensitive key/cert filename detected" "$file" "0" "(id_rsa|id_ed25519|\.pem|\.p12|\.pfx)$" "Remove and rotate credentials if exposed. Add to .gitignore." "CHECK_19"
            found=1
        done <<< "$hits"
    fi
    
    [[ $found -eq 0 ]] && check_pass "No obvious key/cert filenames found"
}

check_20_output_js_key_exposure() {
    check_header "20" "Output JS Key Exposure (Heuristic)"
    
    [[ -z "${OUTPUT_DIR}" || ! -d "${OUTPUT_DIR}" ]] && check_info "No build output directory detected" && return 0
    
    local pattern='(AIza[0-9A-Za-z\-_]{35}|AKIA[0-9A-Z]{16}|xox[baprs]-[0-9A-Za-z-]{10,}|ghp_[0-9A-Za-z]{30,})'
    local tmpf found=0
    tmpf="$(tmpfile output-keys-check)"
    
    grep -RIn --exclude="*.map" -E "$pattern" "${OUTPUT_DIR}" 2>/dev/null > "$tmpf" || true
    
    if [[ -s "$tmpf" ]]; then
        local count=0
        while IFS=: read -r file line_num matched && [[ $count -lt 5 ]]; do
            add_finding "$SEVERITY_HIGH" "Possible API key in bundle" "$file" "$line_num" "$pattern" "Remove keys from client-side bundles. Use server-side injection." "CHECK_20"
            found=1
            ((++count))
        done < "$tmpf"
    fi
    
    [[ $found -eq 0 ]] && check_pass "No obvious keys in output bundles"
}

check_21_netlify_redirects() {
    check_header "21" "Netlify Redirects (Hint)"
    
    if [[ -f "netlify.toml" ]]; then
        if grep -qE 'status\s*=\s*30[12]' netlify.toml 2>/dev/null; then
            check_pass "Redirect rules detected"
        else
            check_info "No redirect rules detected in netlify.toml"
        fi
    else
        check_info "netlify.toml not found"
    fi
}

check_22_cname() {
    check_header "22" "CNAME / GitHub Pages File"
    
    if [[ -f "CNAME" ]]; then
        check_pass "CNAME file found"
    else
        check_info "No CNAME file found (ok if not using custom domain)"
    fi
}

check_23_htaccess() {
    check_header "23" "Server Config Artifacts (.htaccess)"
    
    local hits found=0
    hits="$(find . -maxdepth 4 -type f -name ".htaccess" -print 2>/dev/null | head -n 5 || true)"
    
    if [[ -n "${hits}" ]]; then
        while IFS= read -r file ; do
            [[ -z "$file" ]] && continue
            add_finding "$SEVERITY_LOW" ".htaccess present" "$file" "0" "\.htaccess$" "Verify rules are safe and don't expose sensitive paths" "CHECK_23"
            found=1
        done <<< "$hits"
    fi
    
    [[ $found -eq 0 ]] && check_pass "No .htaccess files found"
}

check_24_exposed_configs_output() {
    check_header "24" "Exposed Config Files (Output)"
    
    [[ -z "${OUTPUT_DIR}" || ! -d "${OUTPUT_DIR}" ]] && check_info "No build output directory detected" && return 0
    
    local hits found=0
    hits="$(find "${OUTPUT_DIR}" -type f \
        \( -name ".env" -o -name "*.pem" -o -name "*.key" -o -name "*.p12" -o -name "*.pfx" -o -name "*.bak" -o -name "*.old" \) \
        -print 2>/dev/null | head -n 10 || true)"
    
    if [[ -n "${hits}" ]]; then
        while IFS= read -r file ; do
            [[ -z "$file" ]] && continue
            add_finding "$SEVERITY_CRITICAL" "Sensitive config/key artifact in output" "$file" "0" "(\.env|\.pem|\.key|\.p12|\.pfx|\.bak|\.old)$" "Remove from output and fix build exclusions" "CHECK_24"
            found=1
        done <<< "$hits"
    fi
    
    [[ $found -eq 0 ]] && check_pass "No exposed config/key artifacts in output"
}

check_25_netlify_env_leak() {
    check_header "25" "Netlify Env Leak Heuristic"
    
    [[ ! -f "netlify.toml" ]] && check_info "netlify.toml not found" && return 0
    
    local pattern='(API_KEY|SECRET|TOKEN|PASSWORD)\s*='
    local tmpf found=0
    tmpf="$(tmpfile netlify-secrets)"
    
    grep -n -E "$pattern" netlify.toml 2>/dev/null > "$tmpf" || true
    
    if [[ -s "$tmpf" ]]; then
        while IFS=: read -r line_num match; do
            add_finding "$SEVERITY_HIGH" "Possible secret in netlify.toml" "netlify.toml" "$line_num" "$pattern" "Move secrets to Netlify environment variables / secret store" "CHECK_25"
            found=1
            break
        done < "$tmpf"
    fi
    
    [[ $found -eq 0 ]] && check_pass "No obvious secrets in netlify.toml"
}

check_26_hugo_modules() {
    check_header "26" "Hugo Modules / Themes"
    
    [[ "$GENERATOR" != "hugo" ]] && check_info "Not Hugo (skipping)" && return 0
    
    if [[ -f "go.mod" ]]; then
        check_pass "go.mod present (modules in use)"
    else
        check_info "go.mod not found (modules may not be used)"
    fi
}

check_27_jekyll_plugins() {
    check_header "27" "Jekyll Plugins (Hint)"
    
    [[ "$GENERATOR" != "jekyll" ]] && check_info "Not Jekyll (skipping)" && return 0
    
    if [[ -f "_config.yml" ]] && grep -qE '^plugins:' _config.yml 2>/dev/null; then
        check_info "Jekyll plugins configured (verify trusted sources)"
    else
        check_pass "No plugins section detected in Jekyll config"
    fi
}

check_28_astro_integrations() {
    check_header "28" "Astro Integrations (Hint)"
    
    [[ "$GENERATOR" != "astro" ]] && check_info "Not Astro (skipping)" && return 0
    
    local hits
    hits="$(grep -RIn -E 'integrations\s*:\s*\[' astro.config.* 2>/dev/null | head -n 10 || true)"
    
    if [[ -n "${hits}" ]]; then
        check_info "Astro integrations detected (verify trusted sources)"
    else
        check_pass "No obvious integrations array found"
    fi
}

check_29_eleventy_eval() {
    check_header "29" "Eleventy eval/Function (Hint)"
    
    [[ "$GENERATOR" != "eleventy" ]] && check_info "Not Eleventy (skipping)" && return 0
    
    local hits found=0
    hits="$(grep -RIn --exclude-dir=".git" --exclude-dir="node_modules" -E 'eval\(|Function\(' . 2>/dev/null | head -n 10 || true)"
    
    if [[ -n "${hits}" ]]; then
        local count=0
        while IFS=: read -r file line_num match && [[ $count -lt 3 ]]; do
            add_finding "$SEVERITY_MEDIUM" "Potential eval/Function usage" "$file" "$line_num" "eval\(|Function\(" "Avoid eval/Function in build tooling where possible" "CHECK_29"
            found=1
            ((++count))
        done <<< "$hits"
    fi
    
    [[ $found -eq 0 ]] && check_pass "No eval/Function usage detected (heuristic)"
}

check_30_next_export() {
    check_header "30" "Next.js Export Output"
    
    [[ "$GENERATOR" != "next" ]] && check_info "Not Next.js (skipping)" && return 0
    
    if [[ -d "out" ]]; then
        check_pass "out/ directory present (export output)"
    else
        check_info "out/ not found (may not be exported build)"
    fi
}

check_31_large_files() {
    check_header "31" "Large Files"
    
    local hits found=0
    hits="$(find . \
        \( -path "./.git" -o -path "./node_modules" -o -path "./vendor" \) -prune -o \
        -type f -size +20M -print 2>/dev/null | head -n 10 || true)"
    
    if [[ -n "${hits}" ]]; then
        while IFS= read -r file ; do
            [[ -z "$file" ]] && continue
            add_finding "$SEVERITY_LOW" "Large file detected (>20MB)" "$file" "0" "size > 20MB" "Consider Git LFS or exclude from repository" "CHECK_31"
            found=1
        done <<< "$hits"
    fi
    
    [[ $found -eq 0 ]] && check_pass "No large files detected"
}

check_32_precommit_hook() {
    check_header "32" "Git Hooks (pre-commit)"
    
    if [[ -f ".git/hooks/pre-commit" ]]; then
        check_pass ".git/hooks/pre-commit present"
    else
        check_info "No pre-commit hook found (consider installing)"
    fi
}

check_33_readme() {
    check_header "33" "README Presence"
    
    if [[ -f "README.md" || -f "readme.md" ]]; then
        check_pass "README present"
    else
        check_info "No README found (consider adding project documentation)"
    fi
}

check_34_actions_footguns() {
    check_header "34" "GitHub Actions Foot-guns"
    
    [[ ! -d ".github/workflows" ]] && check_info "No .github/workflows directory" && return 0
    
    local pattern='(pull_request_target|curl[^|]*\|\s*(bash|sh)|wget[^|]*\|\s*(bash|sh)|\bset\s+-x\b|secrets\.)'
    local tmpf found=0
    tmpf="$(tmpfile workflow-footguns)"
    
    grep -RIn -E "$pattern" .github/workflows 2>/dev/null > "$tmpf" || true
    
    if [[ -s "$tmpf" ]]; then
        local count=0
        while IFS=: read -r file line_num matched && [[ $count -lt 3 ]]; do
            add_finding "$SEVERITY_MEDIUM" "Potential workflow foot-gun" "$file" "$line_num" "$pattern" "Avoid pull_request_target unless you understand trust boundaries. Avoid curl|bash. Avoid echoing secrets." "CHECK_34"
            found=1
            ((++count))
        done < "$tmpf"
    fi
    
    [[ $found -eq 0 ]] && check_pass "No common workflow foot-guns detected"
}

check_35_actions_pinning() {
    check_header "35" "Actions Pinning & Permissions"
    
    [[ ! -d ".github/workflows" ]] && check_info "No .github/workflows directory" && return 0

    local unpinned writeall hasperms found=0
    unpinned="$(grep -RIn -E '^\s*uses:\s*[^#]+@([A-Za-z0-9_.-]+)\s*$' .github/workflows 2>/dev/null \
        | grep -v -E '@[0-9a-f]{40}\b' 2>/dev/null \
        | grep -v -E 'uses:\s*\./' 2>/dev/null \
        | head -n 50 || true)"

    writeall="$(grep -RIn -E '^\s*permissions:\s*write-all\b' .github/workflows 2>/dev/null | head -n 20 || true)"
    hasperms="$(grep -RIn -E '^\s*permissions:\s*$' .github/workflows 2>/dev/null | head -n 5 || true)"

    if [[ -n "${unpinned}" ]]; then
        local count=0
        while IFS=: read -r file line_num match && [[ $count -lt 3 ]]; do
            add_finding "$SEVERITY_MEDIUM" "Action not pinned to commit SHA" "$file" "$line_num" "uses:.*@[^0-9a-f]" "Pin actions to full commit SHAs (supply chain hardening)" "CHECK_35"
            found=1
            ((++count))
        done <<< "$unpinned"
    fi

    if [[ -n "${writeall}" ]]; then
        while IFS=: read -r file line_num match; do
            add_finding "$SEVERITY_MEDIUM" "permissions: write-all detected" "$file" "$line_num" "permissions:\s*write-all" "Use least-privilege permissions (e.g., contents: read)" "CHECK_35"
            found=1
        done <<< "$writeall"
    fi

    if [[ -z "${hasperms}" ]]; then
        add_finding "$SEVERITY_LOW" "No explicit permissions block" ".github/workflows" "0" "" "Add a top-level permissions: block to workflows" "CHECK_35"
        found=1
    fi
    
    [[ $found -eq 0 ]] && check_pass "Actions properly pinned and scoped"
}

check_36_lockfile() {
    check_header "36" "Lockfile Hygiene"
    
    [[ ! -f "package.json" ]] && check_info "package.json not found" && return 0
    
    if [[ ! -f "package-lock.json" && ! -f "pnpm-lock.yaml" && ! -f "yarn.lock" ]]; then
        add_finding "$SEVERITY_MEDIUM" "package.json present but no lockfile" "package.json" "0" "" "Commit a lockfile (package-lock.json / pnpm-lock.yaml / yarn.lock) to reduce supply-chain drift" "CHECK_36"
    else
        check_pass "Lockfile present"
    fi
}

check_37_security_txt() {
    check_header "37" "security.txt Presence"
    
    local found=0
    [[ -f ".well-known/security.txt" || -f "security.txt" ]] && found=1
    [[ -n "${OUTPUT_DIR}" && ( -f "${OUTPUT_DIR}/.well-known/security.txt" || -f "${OUTPUT_DIR}/security.txt" ) ]] && found=1
    
    if [[ "${found}" -eq 1 ]]; then
        check_pass "security.txt detected"
    else
        add_finding "$SEVERITY_LOW" "security.txt missing" "." "0" "" "Add /.well-known/security.txt with contact for vulnerability reports" "CHECK_37"
    fi
}

check_38_csp_quality() {
    check_header "38" "CSP Quality (Netlify)"
    
    [[ ! -f "netlify.toml" ]] && check_info "netlify.toml not found" && return 0
    
    local csp found=0
    csp="$(grep -n -E 'Content-Security-Policy' netlify.toml 2>/dev/null | head -n 3 || true)"
    
    if [[ -z "${csp}" ]]; then
        add_finding "$SEVERITY_LOW" "No Content-Security-Policy header" "netlify.toml" "0" "Content-Security-Policy" "Add a CSP header (even basic) to reduce XSS impact" "CHECK_38"
        found=1
    else
        check_pass "CSP header found"
        if echo "${csp}" | grep -qi -E 'unsafe-inline|unsafe-eval' 2>/dev/null; then
            local line_num
            line_num=$(echo "${csp}" | head -1 | cut -d: -f1)
            add_finding "$SEVERITY_LOW" "CSP includes unsafe-*" "netlify.toml" "$line_num" "unsafe-(inline|eval)" "Remove unsafe-* where possible; use nonces/hashes" "CHECK_38"
            found=1
        fi
    fi
    
    [[ $found -eq 0 ]] && check_pass "CSP configured without unsafe directives"
}

check_39_browser_headers() {
    check_header "39" "Browser Hardening Headers (Netlify)"
    
    [[ ! -f "netlify.toml" ]] && check_info "netlify.toml not found" && return 0

    local rp pp coop coep found=0
    rp="$(grep -n -E 'Referrer-Policy' netlify.toml 2>/dev/null | head -n 1 || true)"
    pp="$(grep -n -E 'Permissions-Policy' netlify.toml 2>/dev/null | head -n 1 || true)"
    coop="$(grep -n -E 'Cross-Origin-Opener-Policy' netlify.toml 2>/dev/null | head -n 1 || true)"
    coep="$(grep -n -E 'Cross-Origin-Embedder-Policy' netlify.toml 2>/dev/null | head -n 1 || true)"

    [[ -z "${rp}" ]] && add_finding "$SEVERITY_LOW" "Missing Referrer-Policy" "netlify.toml" "0" "Referrer-Policy" "Add Referrer-Policy header" "CHECK_39" && found=1
    [[ -z "${pp}" ]] && add_finding "$SEVERITY_LOW" "Missing Permissions-Policy" "netlify.toml" "0" "Permissions-Policy" "Add Permissions-Policy header" "CHECK_39" && found=1
    [[ -z "${coop}" ]] && add_finding "$SEVERITY_LOW" "Missing Cross-Origin-Opener-Policy" "netlify.toml" "0" "Cross-Origin-Opener-Policy" "Add COOP header" "CHECK_39" && found=1
    [[ -z "${coep}" ]] && add_finding "$SEVERITY_LOW" "Missing Cross-Origin-Embedder-Policy" "netlify.toml" "0" "Cross-Origin-Embedder-Policy" "Add COEP header" "CHECK_39" && found=1
    
    [[ $found -eq 0 ]] && check_pass "All browser hardening headers present"
}

check_40_robots_sitemap() {
    check_header "40" "robots.txt & sitemap.xml Sanity (Output)"
    
    [[ -z "${OUTPUT_DIR}" || ! -d "${OUTPUT_DIR}" ]] && check_info "No build output directory detected" && return 0
    
    local found=0
    
    if [[ -f "${OUTPUT_DIR}/robots.txt" ]]; then
        check_pass "robots.txt found in output"
    else
        add_finding "$SEVERITY_LOW" "robots.txt not found in output" "${OUTPUT_DIR}" "0" "" "Add robots.txt to control indexing (especially for staging/drafts)" "CHECK_40"
        found=1
    fi

    if [[ -f "${OUTPUT_DIR}/sitemap.xml" ]]; then
        local pattern='(draft|internal|admin|/\.env|/\.git)'
        local bad
        bad="$(grep -n -E "$pattern" "${OUTPUT_DIR}/sitemap.xml" 2>/dev/null | head -n 20 || true)"
        if [[ -n "${bad}" ]]; then
            local line_num
            line_num=$(echo "$bad" | head -1 | cut -d: -f1)
            add_finding "$SEVERITY_MEDIUM" "sitemap.xml includes sensitive paths" "${OUTPUT_DIR}/sitemap.xml" "$line_num" "$pattern" "Exclude drafts/admin/internal paths from sitemap generation" "CHECK_40"
            found=1
        else
            check_pass "sitemap.xml looks sane"
        fi
    else
        check_info "sitemap.xml not found in output"
    fi
}

check_41_storage_endpoints() {
    check_header "41" "Public Storage Endpoints (Output)"
    
    [[ -z "${OUTPUT_DIR}" || ! -d "${OUTPUT_DIR}" ]] && check_info "No build output directory detected" && return 0
    
    local pattern='(s3\.amazonaws\.com|\.s3\.amazonaws\.com|storage\.googleapis\.com|\.blob\.core\.windows\.net)'
    local hits found=0
    hits="$(grep -RIn --exclude="*.map" -E "$pattern" "${OUTPUT_DIR}" 2>/dev/null | head -n 20 || true)"
    
    if [[ -n "${hits}" ]]; then
        local count=0
        while IFS=: read -r file line_num match && [[ $count -lt 3 ]]; do
            add_finding "$SEVERITY_LOW" "Cloud storage endpoint referenced" "$file" "$line_num" "$pattern" "Confirm buckets/containers are intentional and properly scoped" "CHECK_41"
            found=1
            ((++count))
        done <<< "$hits"
    fi
    
    [[ $found -eq 0 ]] && check_pass "No common cloud storage endpoints found"
}

check_42_recon_breadcrumbs() {
    check_header "42" "Recon Breadcrumbs (Output)"
    
    [[ -z "${OUTPUT_DIR}" || ! -d "${OUTPUT_DIR}" ]] && check_info "No build output directory detected" && return 0
    
    local pattern='(/wp-admin|/phpmyadmin|/admin\b|/graphql\b|/\.env\b|/\.git\b)'
    local hits found=0
    hits="$(grep -RIn --exclude="*.map" -E "$pattern" "${OUTPUT_DIR}" 2>/dev/null | head -n 20 || true)"
    
    if [[ -n "${hits}" ]]; then
        local count=0
        while IFS=: read -r file line_num match && [[ $count -lt 3 ]]; do
            add_finding "$SEVERITY_LOW" "Potential recon breadcrumb" "$file" "$line_num" "$pattern" "Remove unnecessary endpoint references from public pages" "CHECK_42"
            found=1
            ((++count))
        done <<< "$hits"
    fi
    
    [[ $found -eq 0 ]] && check_pass "No common recon breadcrumbs found"
}

check_43_exfil_indicators() {
    check_header "43" "Exfiltration Indicators"
    
    [[ "$ONLY_OUTPUT" -eq 1 ]] && check_info "Skipping source scan (--only-output)" && return 0
    
    local pattern='(webhook\.site|requestbin|ngrok\.io|hookdeck\.com|pipedream\.net|pastebin\.com|discord(app)?\.com/api/webhooks)'
    local tmpf found=0
    tmpf="$(tmpfile exfil-indicators)"
    
    grep -RIn --exclude-dir=".git" --exclude-dir="node_modules" --exclude="*.sh" \
        -E "$pattern" . 2>/dev/null > "$tmpf" || true
    
    if [[ -s "$tmpf" ]]; then
        local count=0
        while IFS=: read -r file line_num matched && [[ $count -lt 5 ]]; do
            add_finding "$SEVERITY_MEDIUM" "Potential exfiltration endpoint" "$file" "$line_num" "$pattern" "Confirm endpoints are intentional. Treat unexpected webhooks as compromise indicator." "CHECK_43"
            found=1
            ((++count))
        done < "$tmpf"
    fi
    
    [[ $found -eq 0 ]] && check_pass "No exfiltration endpoint indicators found"
}

check_44_hook_permissions() {
    check_header "44" "Git Hook Permissions"
    
    [[ ! -f ".git/hooks/pre-commit" ]] && check_info "No pre-commit hook found" && return 0

    local found=0
    
    if [[ ! -x ".git/hooks/pre-commit" ]]; then
        add_finding "$SEVERITY_LOW" "pre-commit hook not executable" ".git/hooks/pre-commit" "0" "" "chmod +x .git/hooks/pre-commit" "CHECK_44"
        found=1
    fi

    local mode=""
    mode="$(stat -c %a .git/hooks/pre-commit 2>/dev/null || stat -f %OLp .git/hooks/pre-commit 2>/dev/null || true)"
    if [[ -n "${mode}" ]]; then
        local last="${mode: -1}"
        if [[ "${last}" =~ ^[2367]$ ]]; then
            add_finding "$SEVERITY_MEDIUM" "pre-commit hook writable by others" ".git/hooks/pre-commit" "0" "mode ${mode}" "chmod 700 .git/hooks/pre-commit" "CHECK_44"
            found=1
        fi
    fi
    
    [[ $found -eq 0 ]] && check_pass "pre-commit hook permissions correct"
}

check_45_dependabot() {
    check_header "45" "Dependabot Config"
    
    local has_deps=0
    [[ -f "package.json" || -f "go.mod" || -f "requirements.txt" || -f "Gemfile" ]] && has_deps=1
    
    if [[ "${has_deps}" -eq 0 ]]; then
        check_info "No obvious dependency manifests detected"
        return 0
    fi
    
    if [[ -f ".github/dependabot.yml" || -f ".github/dependabot.yaml" ]]; then
        check_pass "Dependabot config detected"
    else
        add_finding "$SEVERITY_LOW" "Dependabot config missing" "." "0" "" "Add .github/dependabot.yml to keep dependencies fresh" "CHECK_45"
    fi
}

# ============================================
# IaC & CI/CD Pipeline Security Checks (46-53)
# ============================================

check_46_iac_hardcoded_secrets() {
    check_header "46" "IaC Hardcoded Secrets"

    [[ "$ONLY_OUTPUT" -eq 1 ]] && check_info "Skipping source scan (--only-output)" && return 0

    # Target files: Terraform, TFVars, Docker Compose, CloudFormation templates (common extensions)
    local iac_files
    iac_files=$(find . \
        \( -path "./.git" -o -path "./node_modules" -o -path "./vendor" -o -path "./.terraform" \) -prune -o \
        -type f \( \
            -name "*.tf" -o \
            -name "*.tfvars" -o \
            -name "docker-compose*.yml" -o \
            -name "docker-compose*.yaml" -o \
            -name "*-stack.yml" -o \
            -name "*-stack.yaml" -o \
            -name "*.template" -o \
            -name "*.template.json" -o \
            -name "*.template.yaml" -o \
            -name "*.template.yml" -o \
            -name "*.cf.yml" -o \
            -name "*.cf.yaml" -o \
            -name "*.cfn.yml" -o \
            -name "*.cfn.yaml" \
        \) -print 2>/dev/null)

    [[ -z "$iac_files" ]] && check_info "No IaC files detected" && return 0

    local found=0

    # Pattern 1: AWS Access Keys (AKIA...)
    local aws_pattern='AKIA[A-Z0-9]{16}'

    # Pattern 2: Generic secret-looking assignments (quoted values)
    local secret_assignment_pattern='(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|token)\s*[=:]\s*["'"'"'][^"'"'"'\s]{8,}["'"'"']'

    # Pattern 3: Database connection strings with credentials
    local db_conn_pattern='(mysql|postgres|mongodb|mariadb|sqlserver):\/\/[^:]+:[^@]+@'

    # Pattern 4: Private keys
    local private_key_pattern='-----BEGIN[[:space:]].*PRIVATE KEY-----'

    local -a patterns=(
        "$aws_pattern"
        "$secret_assignment_pattern"
        "$db_conn_pattern"
        "$private_key_pattern"
    )

    while IFS= read -r file ; do
        [[ -z "$file" || ! -f "$file" ]] && continue
        should_ignore_file "$file" && continue

        # Skip non-text files
        file "$file" 2>/dev/null | grep -q text || continue

        local pattern
        for pattern in "${patterns[@]}"; do
            while IFS=: read -r line_num match; do
                [[ -z "$line_num" ]] && continue

                # Skip obvious placeholders / examples
                echo "$match" | grep -qiE '(example|placeholder|changeme|your_|xxx|dummy|sample)' && continue

                local severity="$SEVERITY_HIGH"
                local message="Hardcoded secret in IaC file"

                # Elevate to CRITICAL for AWS key or private key
                if echo "$match" | grep -qE "$aws_pattern|$private_key_pattern"; then
                    severity="$SEVERITY_CRITICAL"
                    message="Hardcoded credential in IaC (AWS key or private key)"
                fi

                add_finding "$severity" "$message" "$file" "$line_num" "$pattern" \
                    "Remove hardcoded secrets. Use variables marked sensitive, AWS Secrets Manager, HashiCorp Vault, or encrypted parameter stores. Rotate exposed credentials immediately." \
                    "CHECK_46"
                found=1
            done < <(grep -n -E "$pattern" "$file" 2>/dev/null || true)
        done
    done <<< "$iac_files"

    [[ $found -eq 0 ]] && check_pass "No hardcoded secrets in IaC files"
}

check_47_insecure_docker_base_images() {
    check_header "47" "Insecure Docker Base Images"

    [[ "$ONLY_OUTPUT" -eq 1 ]] && check_info "Skipping source scan (--only-output)" && return 0

    local dockerfiles
    dockerfiles=$(find . \
        \( -path "./.git" -o -path "./node_modules" -o -path "./vendor" \) -prune -o \
        -type f \( -name "Dockerfile" -o -name "Dockerfile.*" -o -name "*.dockerfile" \) \
        -print 2>/dev/null)

    [[ -z "$dockerfiles" ]] && check_info "No Dockerfiles detected" && return 0

    local found=0

    # Known EOL / risky base images (heuristic list)
    local vulnerable_images='(node:10|node:12|python:2\.|ubuntu:16\.04|debian:jessie|debian:stretch|alpine:3\.[0-8]\b)'

    while IFS= read -r file ; do
        [[ -z "$file" || ! -f "$file" ]] && continue
        should_ignore_file "$file" && continue

        # Check 1: :latest tag usage
        while IFS=: read -r line_num match; do
            [[ -z "$line_num" ]] && continue
            add_finding "$SEVERITY_MEDIUM" "Dockerfile uses :latest tag" "$file" "$line_num" \
                "FROM.*:latest" \
                "Pin to specific image versions (e.g., FROM node:20.11-alpine). Latest tags break reproducibility and introduce supply chain drift." \
                "CHECK_47"
            found=1
            break
        done < <(grep -n -E '^\s*FROM\s+[^:[:space:]]+:latest\b' "$file" 2>/dev/null || true)

        # Check 2: FROM with no tag at all (defaults to :latest)
        while IFS=: read -r line_num match; do
            [[ -z "$line_num" ]] && continue
            add_finding "$SEVERITY_MEDIUM" "Dockerfile base image has no version tag" "$file" "$line_num" \
                '^\s*FROM\s+[A-Za-z0-9/_-]+\s*$' \
                "Specify explicit version tags (e.g., FROM ubuntu:22.04). Untagged images default to :latest." \
                "CHECK_47"
            found=1
            break
        done < <(grep -n -E '^\s*FROM\s+[A-Za-z0-9/_-]+\s*$' "$file" 2>/dev/null || true)

        # Check 3: Known vulnerable/EOL base images
        while IFS=: read -r line_num match; do
            [[ -z "$line_num" ]] && continue
            add_finding "$SEVERITY_HIGH" "Dockerfile uses known EOL/vulnerable base image" "$file" "$line_num" \
                "$vulnerable_images" \
                "Update to supported base image versions. EOL images no longer receive security patches." \
                "CHECK_47"
            found=1
            break
        done < <(grep -n -E "^\s*FROM\s+.*${vulnerable_images}" "$file" 2>/dev/null || true)

        # Check 4: Running as root at end of build (last USER is root)
        local last_user_line last_user
        last_user_line=$(grep -n -E '^\s*USER\s+[^#[:space:]]+' "$file" 2>/dev/null | tail -1 || true)
        if [[ -n "$last_user_line" ]]; then
            last_user=$(echo "$last_user_line" | sed -E 's/^[0-9]+:\s*USER\s+([^#[:space:]]+).*/\1/' | tr -d '\r')
            if [[ "$last_user" == "root" ]]; then
                local line_num
                line_num=$(echo "$last_user_line" | cut -d: -f1)
                add_finding "$SEVERITY_MEDIUM" "Dockerfile runs as root (last USER is root)" "$file" "$line_num" \
                    "USER root" \
                    "Drop privileges by setting a non-root user near the end of the Dockerfile (e.g., USER node). Running as root violates least privilege." \
                    "CHECK_47"
                found=1
            fi
        fi
    done <<< "$dockerfiles"

    [[ $found -eq 0 ]] && check_pass "Docker configurations follow security best practices"
}

check_48_overly_permissive_iac() {
    check_header "48" "Overly Permissive IAM/Network Rules"

    [[ "$ONLY_OUTPUT" -eq 1 ]] && check_info "Skipping source scan (--only-output)" && return 0

    local iac_files
    iac_files=$(find . \
        \( -path "./.git" -o -path "./node_modules" -o -path "./vendor" -o -path "./.terraform" \) -prune -o \
        -type f \( -name "*.tf" -o -name "*.template" -o -name "*.template.json" -o -name "*.template.yaml" -o -name "*.template.yml" \) \
        -print 2>/dev/null)

    [[ -z "$iac_files" ]] && check_info "No IaC files detected" && return 0

    local found=0

    while IFS= read -r file ; do
        [[ -z "$file" || ! -f "$file" ]] && continue
        should_ignore_file "$file" && continue

        file "$file" 2>/dev/null | grep -q text || continue

        # 1) 0.0.0.0/0 in likely ingress contexts
        local cidr_all_pattern='(cidr_blocks\s*=\s*\[[^]]*"0\.0\.0\.0\/0"|CidrIp[^:]*:\s*["'"'"']?0\.0\.0\.0\/0)'
        while IFS=: read -r line_num match; do
            [[ -z "$line_num" ]] && continue

            # Skip obvious egress/outbound blocks
            local context
            context=$(sed -n "$((line_num-5)),$((line_num+2))p" "$file" 2>/dev/null || true)
            echo "$context" | grep -qiE 'egress|outbound' && continue

            add_finding "$SEVERITY_HIGH" "Network rule allows access from anywhere (0.0.0.0/0)" "$file" "$line_num" \
                "$cidr_all_pattern" \
                "Restrict ingress to specific IP ranges. Prefer security group references or VPC CIDR blocks. Public ingress should be rare and intentional." \
                "CHECK_48"
            found=1
        done < <(grep -n -E "$cidr_all_pattern" "$file" 2>/dev/null || true)

        # 2) IAM policy wildcards (Action: *, Resource: *) — JSON or Terraform-style
        local iam_wildcard_pattern='("Action"\s*:\s*"\*"|"Resource"\s*:\s*"\*"|actions\s*=\s*\[[^]]*"\*"[^]]*\]|resources\s*=\s*\[[^]]*"\*"[^]]*\])'
        while IFS=: read -r line_num match; do
            [[ -z "$line_num" ]] && continue
            add_finding "$SEVERITY_HIGH" "IAM policy grants wildcard permissions" "$file" "$line_num" \
                "$iam_wildcard_pattern" \
                "Scope permissions to specific actions and resources. Use least privilege: grant only what is required, for specific resources." \
                "CHECK_48"
            found=1
        done < <(grep -n -E "$iam_wildcard_pattern" "$file" 2>/dev/null || true)

        # 3) S3 bucket public access indicators (heuristic)
        local s3_public_pattern='(acl\s*=\s*"public-read"|acl\s*=\s*"public-read-write"|BlockPublicAcls[^:]*:\s*false|IgnorePublicAcls[^:]*:\s*false|RestrictPublicBuckets[^:]*:\s*false)'
        while IFS=: read -r line_num match; do
            [[ -z "$line_num" ]] && continue
            add_finding "$SEVERITY_CRITICAL" "S3 bucket configured for public access" "$file" "$line_num" \
                "$s3_public_pattern" \
                "Enable S3 Block Public Access unless public hosting is explicitly required. Prefer CloudFront + OAC/OAI for public content distribution." \
                "CHECK_48"
            found=1
        done < <(grep -n -E "$s3_public_pattern" "$file" 2>/dev/null || true)

    done <<< "$iac_files"

    [[ $found -eq 0 ]] && check_pass "No overly permissive IAM/network rules detected"
}

check_49_infrastructure_drift() {
    check_header "49" "Infrastructure Drift Detection (Heuristic)"

    [[ "$ONLY_OUTPUT" -eq 1 ]] && check_info "Skipping source scan (--only-output)" && return 0

    local found=0

    # 1) Terraform state files should never be committed
    local state_files
    state_files=$(find . \
        \( -path "./.git" -o -path "./node_modules" -o -path "./vendor" -o -path "./.terraform" \) -prune -o \
        -type f -name "terraform.tfstate" -print 2>/dev/null)

    if [[ -n "$state_files" ]]; then
        while IFS= read -r state_file ; do
            [[ -z "$state_file" || ! -f "$state_file" ]] && continue
            should_ignore_file "$state_file" && continue

            add_finding "$SEVERITY_CRITICAL" "Terraform state file committed to repository" "$state_file" "0" \
                "terraform\.tfstate" \
                "REMOVE IMMEDIATELY. Terraform state files contain sensitive data. Add to .gitignore and use remote backends (S3, Terraform Cloud). If already pushed, rotate credentials referenced in state." \
                "CHECK_49"
            found=1
        done <<< "$state_files"
    fi

    # 2) Orphaned .terraform.lock.hcl without any .tf files in the same directory
    local lock_files
    lock_files=$(find . \
        \( -path "./.git" -o -path "./node_modules" -o -path "./vendor" -o -path "./.terraform" \) -prune -o \
        -type f -name ".terraform.lock.hcl" -print 2>/dev/null)

    if [[ -n "$lock_files" ]]; then
        while IFS= read -r lock_file ; do
            [[ -z "$lock_file" || ! -f "$lock_file" ]] && continue
            should_ignore_file "$lock_file" && continue

            local dir tf_count
            dir=$(dirname "$lock_file")
            tf_count=$(find "$dir" -maxdepth 1 -type f -name "*.tf" 2>/dev/null | wc -l | tr -d ' ')

            if [[ "${tf_count:-0}" -eq 0 ]]; then
                add_finding "$SEVERITY_LOW" "Terraform lock file without corresponding .tf files" "$lock_file" "0" \
                    ".terraform.lock.hcl" \
                    "Orphaned lock file suggests deleted Terraform configs. Verify no infrastructure remains unmanaged or drifting." \
                    "CHECK_49"
                found=1
            fi
        done <<< "$lock_files"
    fi

    # 3) Multiple backend blocks (drift risk indicator)
    local backend_files
    backend_files=$(find . \
        \( -path "./.git" -o -path "./node_modules" -o -path "./vendor" -o -path "./.terraform" \) -prune -o \
        -type f -name "*.tf" -exec grep -l 'backend\s*"' {} \; 2>/dev/null)

    if [[ -n "$backend_files" ]]; then
        local backend_count
        backend_count=$(echo "$backend_files" | wc -l | tr -d ' ')
        if [[ "${backend_count:-0}" -gt 1 ]]; then
            add_finding "$SEVERITY_MEDIUM" "Multiple Terraform backend configurations detected" "." "0" \
                'backend\s*"' \
                "Multiple backends can cause state drift. Consolidate to a single remote backend configuration per workspace/module." \
                "CHECK_49"
            found=1
        fi
    fi

    [[ $found -eq 0 ]] && check_pass "No infrastructure drift indicators detected"
}

check_50_pipeline_secret_injection() {
    check_header "50" "Pipeline Secret Injection Risks"

    local workflow_dir=".github/workflows"
    [[ ! -d "$workflow_dir" ]] && check_info "No .github/workflows directory" && return 0

    local workflow_files
    workflow_files=$(find "$workflow_dir" -type f \( -name "*.yml" -o -name "*.yaml" \) 2>/dev/null)
    [[ -z "$workflow_files" ]] && check_info "No workflow files found" && return 0

    local found=0

    while IFS= read -r file ; do
        [[ -z "$file" || ! -f "$file" ]] && continue
        should_ignore_file "$file" && continue

        # 1) Secrets echoed to logs
        local echo_secret_pattern='(echo[^#\n]*\$\{\{\s*secrets\.|echo[^#\n]*\$[A-Z0-9_]*(SECRET|TOKEN|KEY|PASSWORD))'
        while IFS=: read -r line_num match; do
            [[ -z "$line_num" ]] && continue
            add_finding "$SEVERITY_CRITICAL" "Workflow echoes secret to logs" "$file" "$line_num" \
                "$echo_secret_pattern" \
                "Remove echo statements that output secrets. CI logs can be exposed broadly. Pass secrets via env and avoid printing them." \
                "CHECK_50"
            found=1
        done < <(grep -n -E "$echo_secret_pattern" "$file" 2>/dev/null || true)

        # 2) set -x / xtrace near secret usage
        local setx_pattern='(^|\s)set\s+-[a-zA-Z]*x\b|xtrace'
        while IFS=: read -r line_num match; do
            [[ -z "$line_num" ]] && continue
            local context
            context=$(sed -n "$((line_num)),$((line_num+10))p" "$file" 2>/dev/null || true)
            if echo "$context" | grep -qE '\$\{\{\s*secrets\.|\$[A-Z0-9_]*(SECRET|TOKEN|KEY|PASSWORD)'; then
                add_finding "$SEVERITY_HIGH" "Debug mode (set -x/xtrace) enabled near secret usage" "$file" "$line_num" \
                    "$setx_pattern" \
                    "Remove set -x / xtrace in steps that handle secrets. Debug output expands variables before logging." \
                    "CHECK_50"
                found=1
            fi
        done < <(grep -n -E "$setx_pattern" "$file" 2>/dev/null || true)

        # 3) curl | bash from untrusted domains
        local curl_bash_pattern='curl\s+[^|]*\|\s*(bash|sh)\b'
        while IFS=: read -r line_num match; do
            [[ -z "$line_num" ]] && continue
            echo "$match" | grep -qE '(github\.com|githubusercontent\.com)' && continue
            add_finding "$SEVERITY_MEDIUM" "Workflow pipes curl output directly to shell" "$file" "$line_num" \
                "$curl_bash_pattern" \
                "Download scripts to a file first, verify checksum/source, then execute. Piping to bash enables supply-chain compromise." \
                "CHECK_50"
            found=1
        done < <(grep -n -E "$curl_bash_pattern" "$file" 2>/dev/null || true)

        # 4) pull_request_target + secrets usage
        if grep -qE 'pull_request_target' "$file" 2>/dev/null; then
            if grep -qE '\$\{\{\s*secrets\.' "$file" 2>/dev/null; then
                local line_num
                line_num=$(grep -n -E 'pull_request_target' "$file" 2>/dev/null | head -1 | cut -d: -f1)
                add_finding "$SEVERITY_CRITICAL" "Secrets used in pull_request_target workflow" "$file" "$line_num" \
                    "pull_request_target" \
                    "pull_request_target runs in the base branch context and can expose secrets to untrusted PR code. Prefer pull_request or isolate secret access to trusted code only." \
                    "CHECK_50"
                found=1
            fi
        fi
    done <<< "$workflow_files"

    [[ $found -eq 0 ]] && check_pass "No pipeline secret injection risks detected"
}

check_51_unsigned_container_pushes() {
    check_header "51" "Unsigned Container Image Pushes"

    local workflow_dir=".github/workflows"
    [[ ! -d "$workflow_dir" ]] && check_info "No .github/workflows directory" && return 0

    local workflow_files
    workflow_files=$(find "$workflow_dir" -type f \( -name "*.yml" -o -name "*.yaml" \) 2>/dev/null)
    [[ -z "$workflow_files" ]] && check_info "No workflow files found" && return 0

    local found=0

    while IFS= read -r file ; do
        [[ -z "$file" || ! -f "$file" ]] && continue
        should_ignore_file "$file" && continue

        local docker_push
        docker_push=$(grep -n -E '(docker\s+push|docker\s+buildx[^#\n]*--push|podman\s+push)' "$file" 2>/dev/null || true)
        [[ -z "$docker_push" ]] && continue

        local has_signing
        has_signing=$(grep -iE '(cosign\s+sign|docker\s+trust|notary\s+sign|DOCKER_CONTENT_TRUST=1)' "$file" 2>/dev/null || true)

        if [[ -z "$has_signing" ]]; then
            local line_num
            line_num=$(echo "$docker_push" | head -1 | cut -d: -f1)
            add_finding "$SEVERITY_MEDIUM" "Container image pushed without signing" "$file" "$line_num" \
                '(docker|podman)\s+(buildx\s+)?push' \
                "Implement image signing with Cosign, Docker Content Trust, or Notary. Add signature verification in deployment pipelines." \
                "CHECK_51"
            found=1
        fi

        local unauthenticated_push
        unauthenticated_push=$(grep -n -E 'docker\s+push[^#\n]*localhost:' "$file" 2>/dev/null || true)
        if [[ -n "$unauthenticated_push" ]]; then
            local line_num
            line_num=$(echo "$unauthenticated_push" | head -1 | cut -d: -f1)
            add_finding "$SEVERITY_LOW" "Container push to unauthenticated/local registry" "$file" "$line_num" \
                'docker\s+push.*localhost:' \
                "Even local registries should require auth in CI where feasible. Configure credentials or use managed registries." \
                "CHECK_51"
            found=1
        fi
    done <<< "$workflow_files"

    [[ $found -eq 0 ]] && check_pass "Container builds implement signing or no pushes detected"
}

check_52_build_artifact_tampering() {
    check_header "52" "Build Artifact Tampering Risk"

    local workflow_dir=".github/workflows"
    [[ ! -d "$workflow_dir" ]] && check_info "No .github/workflows directory" && return 0

    local workflow_files
    workflow_files=$(find "$workflow_dir" -type f \( -name "*.yml" -o -name "*.yaml" \) 2>/dev/null)
    [[ -z "$workflow_files" ]] && check_info "No workflow files found" && return 0

    local found=0

    while IFS= read -r file ; do
        [[ -z "$file" || ! -f "$file" ]] && continue
        should_ignore_file "$file" && continue

        local upload
        upload=$(grep -n -E 'actions/upload-artifact|aws\s+s3\s+cp[^#\n]*(dist/|build/|target/|out/)' "$file" 2>/dev/null || true)
        [[ -z "$upload" ]] && continue

        local has_checksum
        has_checksum=$(grep -iE '(sha256sum|shasum|md5sum|checksum)' "$file" 2>/dev/null || true)

        if [[ -z "$has_checksum" ]]; then
            local line_num
            line_num=$(echo "$upload" | head -1 | cut -d: -f1)
            add_finding "$SEVERITY_MEDIUM" "Build artifacts uploaded without integrity verification" "$file" "$line_num" \
                'upload-artifact|s3\s+cp' \
                "Generate and store checksums (prefer SHA-256) for build artifacts. Verify before deploy to detect tampering." \
                "CHECK_52"
            found=1
        fi

        local download
        download=$(grep -n -E 'actions/download-artifact|aws\s+s3\s+cp[^#\n]*download' "$file" 2>/dev/null || true)
        if [[ -n "$download" ]]; then
            local download_line
            download_line=$(echo "$download" | head -1 | cut -d: -f1)
            local context
            context=$(sed -n "$((download_line)),$((download_line+15))p" "$file" 2>/dev/null || true)
            if ! echo "$context" | grep -qiE '(sha256sum\s+-c|shasum\s+-a\s+256\s+-c|verify|checksum)'; then
                add_finding "$SEVERITY_MEDIUM" "Build artifacts downloaded without integrity verification" "$file" "$download_line" \
                    'download-artifact|s3\s+cp.*download' \
                    "Verify artifact integrity after download. Example: sha256sum -c checksums.txt" \
                    "CHECK_52"
                found=1
            fi
        fi
    done <<< "$workflow_files"

    [[ $found -eq 0 ]] && check_pass "Build artifacts include integrity verification"
}

check_53_third_party_action_risk() {
    check_header "53" "Third-Party Action Supply Chain Risk"

    local workflow_dir=".github/workflows"
    [[ ! -d "$workflow_dir" ]] && check_info "No .github/workflows directory" && return 0

    local workflow_files
    workflow_files=$(find "$workflow_dir" -type f \( -name "*.yml" -o -name "*.yaml" \) 2>/dev/null)
    [[ -z "$workflow_files" ]] && check_info "No workflow files found" && return 0

    local found=0

    # Trusted publishers (widely used). These are still better pinned to SHAs.
    local trusted_publishers='^(actions/|github/|docker/|aws-actions/|azure/|google-github-actions/)'

    while IFS= read -r file ; do
        [[ -z "$file" || ! -f "$file" ]] && continue
        should_ignore_file "$file" && continue

        while IFS=: read -r line_num match; do
            [[ -z "$line_num" || -z "$match" ]] && continue

            local action
            action=$(echo "$match" | sed -E 's/.*uses:\s*([^#]+).*/\1/' | tr -d "'\"" | xargs)

            # Skip local actions (./path)
            echo "$action" | grep -qE '^\.' && continue

            # Flag unusual characters
            if echo "$action" | grep -qE '[^a-zA-Z0-9/_@.-]'; then
                add_finding "$SEVERITY_HIGH" "Third-party action reference contains suspicious characters" "$file" "$line_num" \
                    'uses:' \
                    "Action reference contains unusual characters: ${action}. Verify legitimacy before use." \
                    "CHECK_53"
                found=1
            fi

            # Pinning check: prefer full 40-char commit SHA
            if ! echo "$action" | grep -qE '@[0-9a-f]{40}\b'; then
                if echo "$action" | grep -qE "$trusted_publishers"; then
                    add_finding "$SEVERITY_MEDIUM" "GitHub Action not pinned to commit SHA" "$file" "$line_num" \
                        'uses:' \
                        "Pin actions to full commit SHAs (40-char hex). Current: ${action}. Use Dependabot to keep pins updated. Prevents tag hijacking." \
                        "CHECK_53"
                else
                    add_finding "$SEVERITY_MEDIUM" "Untrusted third-party action not pinned to commit SHA" "$file" "$line_num" \
                        'uses:' \
                        "Pin third-party actions to full commit SHAs. Current: ${action}. Consider replacing with a trusted publisher or vendor-maintained action." \
                        "CHECK_53"
                fi
                found=1
            fi
        done < <(grep -n -E '^\s*uses:\s*[^#]+' "$file" 2>/dev/null || true)
    done <<< "$workflow_files"

    [[ $found -eq 0 ]] && check_pass "Actions are SHA-pinned or no risky uses detected"
}


# ============================================
# Output Generation
# ============================================

output_text() {
    [[ $FINDING_COUNT -eq 0 ]] && success "✓ No security issues found" && return
    
    echo ""
    print_color "$RED" "═══════════════════════════════════════════════════════════════════"
    print_color "$RED" " $SCRIPT_NAME v$VERSION — Security Audit Summary"
    print_color "$RED" "═══════════════════════════════════════════════════════════════════"
    echo
    print_color "$YELLOW" "Finding Summary:"
    echo "  Total findings: $FINDING_COUNT"
    [[ $CRITICAL_COUNT -gt 0 ]] && print_color "$RED" "  Critical: $CRITICAL_COUNT"
    [[ $HIGH_COUNT -gt 0 ]] && print_color "$RED" "  High: $HIGH_COUNT"
    [[ $MEDIUM_COUNT -gt 0 ]] && print_color "$YELLOW" "  Medium: $MEDIUM_COUNT"
    [[ $LOW_COUNT -gt 0 ]] && print_color "$BLUE" "  Low: $LOW_COUNT"
    echo
    print_color "$RED" "═══════════════════════════════════════════════════════════════════"
    echo
    
    if [[ $CRITICAL_COUNT -gt 0 ]]; then
        print_color "$RED" "Commit BLOCKED due to CRITICAL findings."
    elif [[ $HIGH_COUNT -gt 0 ]]; then
        print_color "$RED" "Commit BLOCKED due to HIGH findings."
    else
        print_color "$YELLOW" "Review findings before committing."
    fi
    echo
}

output_json() {
    echo "{"
    echo "  \"version\": \"$VERSION\","
    echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
    echo "  \"summary\": { \"total\": $FINDING_COUNT, \"critical\": $CRITICAL_COUNT, \"high\": $HIGH_COUNT, \"medium\": $MEDIUM_COUNT, \"low\": $LOW_COUNT },"
    echo "  \"findings\": ["
    
    for i in "${!FINDING_IDS[@]}"; do
        local check_id="${FINDING_IDS[$i]}" severity="${FINDING_SEVERITIES[$i]}"
        local message="${FINDING_MESSAGES[$i]}" file="${FINDING_FILES[$i]}"
        local line="${FINDING_LINES[$i]}" fingerprint="${FINDING_FINGERPRINTS[$i]}"
        local pattern="${FINDING_PATTERNS[$i]}" action="${FINDING_ACTIONS[$i]}"
        
        message=$(echo "$message" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
        file=$(echo "$file" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
        pattern=$(echo "$pattern" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
        action=$(echo "$action" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
        
        echo -n "    { \"id\": \"$check_id\", \"severity\": \"$severity\", \"message\": \"$message\", \"file\": \"$file\", \"line\": $line, \"pattern\": \"$pattern\", \"action\": \"$action\", \"fingerprint\": \"$fingerprint\" }"
        [[ $i -lt $((FINDING_COUNT - 1)) ]] && echo "," || echo ""
    done
    
    echo "  ]"
    echo "}"
}

output_sarif() {
    echo "{"
    echo "  \"version\": \"2.1.0\","
    echo "  \"\$schema\": \"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json\","
    echo "  \"runs\": ["
    echo "    {"
    echo "      \"tool\": {"
    echo "        \"driver\": {"
    echo "          \"name\": \"$SCRIPT_NAME\","
    echo "          \"version\": \"$VERSION\","
    echo "          \"informationUri\": \"https://bobapotamus.com/zimara\""
    echo "        }"
    echo "      },"
    echo "      \"results\": ["
    
    for i in "${!FINDING_IDS[@]}"; do
        local check_id="${FINDING_IDS[$i]}"
        local severity="${FINDING_SEVERITIES[$i]}"
        local message="${FINDING_MESSAGES[$i]}"
        local file="${FINDING_FILES[$i]}"
        local line="${FINDING_LINES[$i]}"
        local fingerprint="${FINDING_FINGERPRINTS[$i]}"
        local action="${FINDING_ACTIONS[$i]}"
        
        local sarif_level
        case $severity in
            "$SEVERITY_CRITICAL"|"$SEVERITY_HIGH") sarif_level="error" ;;
            "$SEVERITY_MEDIUM") sarif_level="warning" ;;
            "$SEVERITY_LOW") sarif_level="note" ;;
            *) sarif_level="none" ;;
        esac
        
        message=$(echo "$message" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
        file=$(echo "$file" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
        action=$(echo "$action" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
        
        local full_message="$message"
        [[ -n "$action" ]] && full_message="${message}. ${action}"
        
        echo "        {"
        echo "          \"ruleId\": \"$check_id\","
        echo "          \"level\": \"$sarif_level\","
        echo "          \"message\": {"
        echo "            \"text\": \"$full_message\""
        echo "          },"
        echo "          \"locations\": ["
        echo "            {"
        echo "              \"physicalLocation\": {"
        echo "                \"artifactLocation\": {"
        echo "                  \"uri\": \"$file\""
        echo "                },"
        echo "                \"region\": {"
        echo "                  \"startLine\": $line"
        echo "                }"
        echo "              }"
        echo "            }"
        echo "          ],"
        echo "          \"fingerprints\": {"
        echo "            \"0\": \"$fingerprint\""
        echo "          }"
        
        if [[ $i -lt $((FINDING_COUNT - 1)) ]]; then
            echo "        },"
        else
            echo "        }"
        fi
    done
    
    echo "      ]"
    echo "    }"
    echo "  ]"
    echo "}"
}

save_baseline() {
    local baseline_file=$1
    mkdir -p "$(dirname "$baseline_file")"
    output_json > "$baseline_file"
    info "Baseline saved to $baseline_file"
}

# ============================================
# Main Execution
# ============================================

main() {
    parse_arguments "$@"
    [[ "$SHOW_HELP" == true ]] && show_help && exit $EXIT_SUCCESS

    local target_dir
    target_dir="$(resolve_target_dir "${TARGET_PATH:-.}")"

    pushd "$target_dir" >/dev/null
    trap 'popd >/dev/null || true' EXIT

    detect_generator
    load_ignore_patterns
    
    if [[ "$OUTPUT_FORMAT" == "text" ]]; then
        print_color "$PURPLE" "═══════════════════════════════════════════════════════════════════"
        print_color "$PURPLE" " $SCRIPT_NAME v$VERSION — Pre-Commit Security Audit"
        print_color "$PURPLE" " Published by Oob Skulden™"
        print_color "$PURPLE" "═══════════════════════════════════════════════════════════════════"
        echo
        info "Scan directory: ${target_dir}"
        info "Generator: ${GENERATOR}"
        [[ -n "$OUTPUT_DIR" ]] && info "Output directory: ${OUTPUT_DIR}"
        echo
        info "Running 53 comprehensive security checks..."
    fi
    
    # Execute all 53 checks
    check_01_repo_structure
    check_02_gitignore
    check_03_private_keys
    check_04_secret_patterns
    check_05_backup_artifacts
    check_06_dotenv_files
    check_07_output_exposure
    check_08_mixed_content
    check_09_netlify_config
    check_10_netlify_headers
    check_11_github_actions
    check_12_gitleaks
    check_13_detect_secrets
    check_14_npm_audit
    check_15_worktree_clean
    check_16_risky_debug_output
    check_17_git_history_sensitive
    check_18_git_remote_http
    check_19_sensitive_filenames
    check_20_output_js_key_exposure
    check_21_netlify_redirects
    check_22_cname
    check_23_htaccess
    check_24_exposed_configs_output
    check_25_netlify_env_leak
    check_26_hugo_modules
    check_27_jekyll_plugins
    check_28_astro_integrations
    check_29_eleventy_eval
    check_30_next_export
    check_31_large_files
    check_32_precommit_hook
    check_33_readme
    check_34_actions_footguns
    check_35_actions_pinning
    check_36_lockfile
    check_37_security_txt
    check_38_csp_quality
    check_39_browser_headers
    check_40_robots_sitemap
    check_41_storage_endpoints
    check_42_recon_breadcrumbs
    check_43_exfil_indicators
    check_44_hook_permissions
    check_45_dependabot
    check_46_iac_hardcoded_secrets
    check_47_insecure_docker_base_images
    check_48_overly_permissive_iac
    check_49_infrastructure_drift
    check_50_pipeline_secret_injection
    check_51_unsigned_container_pushes
    check_52_build_artifact_tampering
    check_53_third_party_action_risk
    
    # Apply baseline filtering if specified
    [[ -n "$BASELINE_FILE" && "$OUTPUT_FORMAT" == "text" ]] && filter_baseline_findings
    
    # Save baseline if requested
    [[ -n "$SAVE_BASELINE_FILE" ]] && save_baseline "$SAVE_BASELINE_FILE"
    
    # Generate output
    case $OUTPUT_FORMAT in
        json) output_json ;;
        sarif) output_sarif ;;
        text|*) output_text ;;
    esac
    
    # Exit based on findings
    [[ $FINDING_COUNT -gt 0 ]] && exit $EXIT_FINDINGS || exit $EXIT_SUCCESS
}

main "$@"
