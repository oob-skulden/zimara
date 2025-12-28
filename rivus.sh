#!/usr/bin/env bash
# ============================================================
# Ultimate Security Audit Script (v0.42.1 - cleaned)
# Pre-push security sweep for static sites & web projects
#
# Supports: Hugo, Jekyll, Astro, Next export, Eleventy, generic
#
# Published by Oob Skulden™
# "The threats you don't see coming"
# ============================================================

set -euo pipefail

# ============================================================
# CORE HELPERS (REQUIRED)
# ============================================================

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

say()  { printf '%s\n' "$*"; }
sayc() { printf '%b\n' "$*"; }

hr() { sayc "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }

SHOW_MATCHES="${SHOW_MATCHES:-5}"

CRITICAL_ISSUES=0
HIGH_ISSUES=0
MEDIUM_ISSUES=0
LOW_ISSUES=0

# flags
ONLY_OUTPUT=0
SKIP_OUTPUT=0
INCLUDE_OUTPUT_IN_SOURCE=0

# ============================================================
# CLI / USAGE
# ============================================================

usage() {
  cat <<'EOF'
ultimate-security-audit.sh

Usage:
  ./ultimate-security-audit.sh [path] [options]

Options:
  --only-output                 Scan only the output dir (public/dist/out/_site)
  --skip-output                 Skip scanning output dir
  --include-output-in-source     Allow output dir to be git-tracked without warning
  --version                      Print version

Env:
  SHOW_MATCHES=5                How many matching lines to show (default 5)
  OUTPUT_DIR=public             Override detected output directory
  SECRET_TOOL=auto|gitleaks|detect-secrets|git-secrets|none
EOF
}

VERSION="0.42.1"

if [[ "${1:-}" == "--version" ]]; then
  echo "$VERSION"
  exit 0
fi

SCAN_DIR="${1:-.}"
if [[ "${SCAN_DIR:-}" == "--help" || "${SCAN_DIR:-}" == "-h" ]]; then
  usage
  exit 0
fi

ARGS=("$@")
for arg in "${ARGS[@]}"; do
  case "$arg" in
    --only-output) ONLY_OUTPUT=1 ;;
    --skip-output) SKIP_OUTPUT=1 ;;
    --include-output-in-source) INCLUDE_OUTPUT_IN_SOURCE=1 ;;
    --help|-h) usage; exit 0 ;;
    --version) echo "$VERSION"; exit 0 ;;
  esac
done

if [[ ! -d "$SCAN_DIR" ]]; then
  sayc "${RED}✗ Directory not found: $SCAN_DIR${NC}"
  exit 99
fi

cd "$SCAN_DIR"

# ============================================================
# COMMON EXCLUSIONS
# ============================================================

GREP_EXCLUDES=(
  --exclude-dir=.git
  --exclude-dir=node_modules
  --exclude-dir=public
  --exclude-dir=dist
  --exclude-dir=build
  --exclude-dir=vendor
  --exclude-dir=.next
  --exclude-dir=.cache
)

find_prune_args() {
  printf '%s ' \
    -path "./.git" -o \
    -path "./node_modules" -o \
    -path "./public" -o \
    -path "./dist" -o \
    -path "./build" -o \
    -path "./vendor" -o \
    -path "./.next" -o \
    -path "./.cache" \
    -prune
}

_has_cmd() { command -v "$1" >/dev/null 2>&1; }

# ============================================================
# GENERATOR + OUTPUT DETECTION
# ============================================================

GENERATOR="generic"
OUTPUT_DIR_DETECTED=""

if [[ -f "hugo.toml" || -f "hugo.yaml" || -f "hugo.yml" || -f "config.toml" || -f "config.yaml" || -f "config.yml" ]]; then
  GENERATOR="hugo"
  OUTPUT_DIR_DETECTED="public"
elif [[ -f "_config.yml" || -f "_config.yaml" ]]; then
  GENERATOR="jekyll"
  OUTPUT_DIR_DETECTED="_site"
elif [[ -f "astro.config.mjs" || -f "astro.config.js" || -f "astro.config.ts" ]]; then
  GENERATOR="astro"
  OUTPUT_DIR_DETECTED="dist"
elif [[ -f "next.config.js" || -f "next.config.mjs" || -f "next.config.ts" ]]; then
  GENERATOR="next-export"
  OUTPUT_DIR_DETECTED="out"
elif [[ -f ".eleventy.js" || -f "eleventy.config.js" || -f ".eleventy.cjs" ]]; then
  GENERATOR="eleventy"
  OUTPUT_DIR_DETECTED="_site"
fi

# ✅ 2-line OUTPUT_DIR override (env wins, otherwise detected)
OUTPUT_DIR="${OUTPUT_DIR:-$OUTPUT_DIR_DETECTED}"
OUTPUT_BASENAME="$(basename "${OUTPUT_DIR:-}" 2>/dev/null || true)"

# ============================================================
# HEADER
# ============================================================

say ""
sayc "${PURPLE}==============================================${NC}"
sayc "${PURPLE}🔒 ULTIMATE SECURITY AUDIT 🔒  (v${VERSION})${NC}"
sayc "${PURPLE}==============================================${NC}"
say ""
say "Directory scanned: $(pwd)"
say "Generator detected: $GENERATOR"
[[ -n "${OUTPUT_DIR:-}" ]] && say "Output dir detected: $OUTPUT_DIR"
say ""

# ============================================================
# CHECK 1: Private Keys (HARD STOP)
# ============================================================

hr
sayc "${PURPLE}CHECK 1: Private Keys (HARD STOP)${NC}"
hr

KEYS=$(find . \( $(find_prune_args) \) -type f \
  \( -name "*.pem" -o -name "*.key" -o -name "*.p12" -o -name "*.pfx" \) \
  -print 2>/dev/null || true)

if [[ -n "$KEYS" ]]; then
  sayc "${RED}✗ CRITICAL: Private key material found${NC}"
  printf '%s\n' "$KEYS" | sed 's/^/  /'
  say "Actions:"
  say "  • REMOVE immediately"
  say "  • Rotate/revoke keys"
  say "  • Purge git history (git filter-repo/BFG)"
  CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
else
  sayc "${GREEN}✓ No private keys found${NC}"
fi
say ""

# ============================================================
# CHECK 2: Environment / Secrets Files
# ============================================================

hr
sayc "${PURPLE}CHECK 2: Environment / Secrets Files${NC}"
hr

ENV_FILES=$(find . \( $(find_prune_args) \) -type f -name ".env*" -print 2>/dev/null || true)

if [[ -n "$ENV_FILES" ]]; then
  sayc "${RED}✗ Found environment files [CRITICAL]${NC}"
  printf '%s\n' "$ENV_FILES" | sed 's/^/  /'
  say "Actions:"
  say "  • Remove from repo"
  say "  • Add to .gitignore"
  CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
else
  sayc "${GREEN}✓ No .env files found${NC}"
fi
say ""

# ============================================================
# CHECK 3: Hardcoded Credentials
# ============================================================

hr
sayc "${PURPLE}CHECK 3: Hardcoded Credentials${NC}"
hr

CREDS=$(grep -riE "(password|api[_-]?key|secret|token)[[:space:]]*[:=][[:space:]]*['\"][^'\"]{8,}" . \
  "${GREP_EXCLUDES[@]}" 2>/dev/null || true)

if [[ -n "$CREDS" ]]; then
  sayc "${YELLOW}⚠️  Possible hardcoded credentials [HIGH]${NC}"
  printf '%s\n' "$CREDS" | head -"$SHOW_MATCHES" | sed 's/^/  /'
  say "Actions:"
  say "  • Replace with env vars / secret manager references"
  say "  • Rotate exposed values"
  HIGH_ISSUES=$((HIGH_ISSUES + 1))
else
  sayc "${GREEN}✓ No obvious hardcoded credentials${NC}"
fi
say ""

# ============================================================
# DROP-IN: Optional best-in-class secret scanning (gitleaks/detect-secrets/git-secrets)
# ============================================================

SECRET_TOOL="${SECRET_TOOL:-auto}"
SECRET_BASELINE="${SECRET_BASELINE:-.secrets.baseline}"
GITLEAKS_CONFIG="${GITLEAKS_CONFIG:-.gitleaks.toml}"

run_secret_scanner() {
  local dir="${1:-.}"
  local tool="${SECRET_TOOL,,}"

  if [[ "$tool" == "auto" ]]; then
    if _has_cmd gitleaks; then tool="gitleaks"
    elif _has_cmd detect-secrets; then tool="detect-secrets"
    elif _has_cmd git-secrets; then tool="git-secrets"
    else tool="none"
    fi
  fi

  hr
  sayc "${PURPLE}CHECK X: Enhanced Secret Scanning (optional tools)${NC}"
  hr

  case "$tool" in
    none)
      sayc "${BLUE}ℹ️  No external secret scanner found (gitleaks/detect-secrets/git-secrets).${NC}"
      say "  Using built-in checks only."
      say ""
      return 0
      ;;

    gitleaks)
      sayc "${BLUE}ℹ️  Using gitleaks${NC}"
      local report
      report="$(mktemp -t gitleaks-report.XXXXXX.json 2>/dev/null || mktemp "/tmp/gitleaks-report.XXXXXX.json")"
      local -a args
      args=( detect --source "$dir" --report-format json --report-path "$report" )

      if [[ -f "$dir/$GITLEAKS_CONFIG" ]]; then
        args+=( --config "$dir/$GITLEAKS_CONFIG" )
      elif [[ -f "$GITLEAKS_CONFIG" ]]; then
        args+=( --config "$GITLEAKS_CONFIG" )
      fi

      if gitleaks "${args[@]}" >/dev/null 2>&1; then
        sayc "${GREEN}✓ gitleaks: no secrets found${NC}"
        rm -f "$report" >/dev/null 2>&1 || true
        say ""
        return 0
      else
        if [[ -s "$report" ]]; then
          local count
          count="$(grep -c '"RuleID"' "$report" 2>/dev/null || echo 0)"
          sayc "${RED}✗ gitleaks: found ${count} potential secret(s) [CRITICAL]${NC}"
          say "  Report: $report"
          say "Actions:"
          say "  • Validate findings, then rotate/revoke anything real"
          say "  • Consider adding a .gitleaks.toml to reduce false positives"
          CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
          say ""
          return 1
        else
          sayc "${YELLOW}⚠️  gitleaks: scan failed (no report generated).${NC}"
          say "  Tip: run: gitleaks detect --source \"$dir\" -v"
          rm -f "$report" >/dev/null 2>&1 || true
          say ""
          return 3
        fi
      fi
      ;;

    detect-secrets)
      sayc "${BLUE}ℹ️  Using detect-secrets${NC}"
      if [[ -f "$dir/$SECRET_BASELINE" ]]; then
        say "  Baseline: $dir/$SECRET_BASELINE"
        if detect-secrets audit --baseline "$dir/$SECRET_BASELINE" >/dev/null 2>&1; then
          sayc "${GREEN}✓ detect-secrets: baseline audit clean${NC}"
          say ""
          return 0
        else
          sayc "${RED}✗ detect-secrets: potential secrets found vs baseline [CRITICAL]${NC}"
          say "Actions:"
          say "  • Run: detect-secrets audit --baseline \"$dir/$SECRET_BASELINE\""
          CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
          say ""
          return 1
        fi
      else
        local tmp_baseline
        tmp_baseline="$(mktemp -t secrets-baseline.XXXXXX.json 2>/dev/null || mktemp "/tmp/secrets-baseline.XXXXXX.json")"
        if (cd "$dir" && detect-secrets scan) >"$tmp_baseline" 2>/dev/null; then
          local findings
          findings="$(grep -c '"type":' "$tmp_baseline" 2>/dev/null || echo 0)"
          if [[ "${findings:-0}" -gt 0 ]]; then
            sayc "${YELLOW}⚠️  detect-secrets: findings present (baseline not adopted) [HIGH]${NC}"
            say "  Temp baseline: $tmp_baseline"
            say "Actions:"
            say "  • Review + rotate/revoke if real"
            say "  • Or adopt baseline:"
            say "      mv \"$tmp_baseline\" \"$dir/$SECRET_BASELINE\""
            say "      detect-secrets audit --baseline \"$dir/$SECRET_BASELINE\""
            HIGH_ISSUES=$((HIGH_ISSUES + 1))
            say ""
            return 1
          else
            sayc "${GREEN}✓ detect-secrets: no secrets found${NC}"
            rm -f "$tmp_baseline" >/dev/null 2>&1 || true
            say ""
            return 0
          fi
        else
          sayc "${YELLOW}⚠️  detect-secrets: scan failed.${NC}"
          say "  Tip: run: (cd \"$dir\" && detect-secrets scan)"
          rm -f "$tmp_baseline" >/dev/null 2>&1 || true
          say ""
          return 3
        fi
      fi
      ;;

    git-secrets)
      sayc "${BLUE}ℹ️  Using git-secrets${NC}"
      if [[ ! -d "$dir/.git" ]]; then
        sayc "${YELLOW}⚠️  git-secrets works best in a git repo; skipping.${NC}"
        say ""
        return 2
      fi
      if (cd "$dir" && git secrets --scan) >/dev/null 2>&1; then
        sayc "${GREEN}✓ git-secrets: no matches${NC}"
        say ""
        return 0
      else
        sayc "${RED}✗ git-secrets: potential secrets found [CRITICAL]${NC}"
        say "Actions:"
        say "  • Run: (cd \"$dir\" && git secrets --scan) for details"
        CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
        say ""
        return 1
      fi
      ;;

    *)
      sayc "${YELLOW}⚠️  Unknown SECRET_TOOL='$SECRET_TOOL' — skipping external scanner.${NC}"
      say ""
      return 2
      ;;
  esac
}

run_secret_scanner "."

# ============================================================
# CHECK 4: Sensitive Files in Output Directory
# ============================================================

hr
sayc "${PURPLE}CHECK 4: Sensitive Files in Output Directory${NC}"
hr

if [[ "$SKIP_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Output scanning disabled (--skip-output)${NC}"
  say ""
else
  if [[ -n "${OUTPUT_DIR:-}" && -d "${OUTPUT_DIR:-}" ]]; then
    if [[ -d "$OUTPUT_DIR/.git" ]]; then
      sayc "${RED}✗ CRITICAL: .git directory found in output dir!${NC}"
      say "  This can expose your entire git history to the web."
      say "Actions:"
      say "  • Ensure publish folder never includes .git"
      say "  • Confirm host rules prevent serving hidden directories"
      CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
    fi

    OUTPUT_CONFIGS=$(find "$OUTPUT_DIR" -type f \( \
      -name "*.toml" -o -name "*.env" -o -name "*.key" -o -name "*.pem" -o -name "*.p12" -o -name "*.pfx" \
    \) 2>/dev/null | wc -l | tr -d ' ')

    if [[ ${OUTPUT_CONFIGS:-0} -gt 0 ]]; then
      sayc "${RED}✗ Found $OUTPUT_CONFIGS config/key file(s) in output dir [CRITICAL]${NC}"
      find "$OUTPUT_DIR" -type f \( -name "*.toml" -o -name "*.env" -o -name "*.key" -o -name "*.pem" -o -name "*.p12" -o -name "*.pfx" \) 2>/dev/null | sed 's/^/  /'
      say "Actions:"
      say "  • Remove sensitive files from output and rebuild"
      say "  • Ensure they live outside publish dir"
      CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
    else
      sayc "${GREEN}✓ No critical files found in output dir${NC}"
    fi

    SOURCEMAPS=$(find "$OUTPUT_DIR" -name "*.map" 2>/dev/null | wc -l | tr -d ' ')
    if [[ ${SOURCEMAPS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Found $SOURCEMAPS source map file(s) in output dir [MEDIUM]${NC}"
      say "  Source maps can expose original source code and internal paths."
      say "Actions:"
      say "  • Disable sourcemaps for production or restrict access"
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    fi
  else
    sayc "${YELLOW}⚠️  No output directory found - skipping${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 5: Internal URLs/IPs in Output
# ============================================================

hr
sayc "${PURPLE}CHECK 5: Internal URLs/IPs Exposed${NC}"
hr

if [[ "$SKIP_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Output scanning disabled (--skip-output)${NC}"
  say ""
else
  if [[ -n "${OUTPUT_DIR:-}" && -d "${OUTPUT_DIR:-}" ]]; then
    INTERNAL_URLS=$(grep -riE "(localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|\.local|\.internal|docker\.sock)" "$OUTPUT_DIR" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${INTERNAL_URLS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Found $INTERNAL_URLS internal reference(s) [MEDIUM]${NC}"
      grep -riE "(localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|\.local|\.internal|docker\.sock)" "$OUTPUT_DIR" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /' || true
      say "Actions:"
      say "  • Verify baseURL / site URL settings for production"
      say "  • Rebuild with production flags"
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    else
      sayc "${GREEN}✓ No internal URLs/IPs found in output${NC}"
    fi
  else
    sayc "${YELLOW}⚠️  No output directory found - skipping${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 6: Large Files (>10MB)
# ============================================================

hr
sayc "${PURPLE}CHECK 6: Large Files (>10MB)${NC}"
hr

LARGE_FILE_LIST=$(find . \( $(find_prune_args) \) -type f -size +10M -print 2>/dev/null || true)
if [[ -n "$LARGE_FILE_LIST" ]]; then
  LARGE_FILES=$(printf '%s\n' "$LARGE_FILE_LIST" | wc -l | tr -d ' ')
  sayc "${YELLOW}⚠️  Found $LARGE_FILES file(s) larger than 10MB [MEDIUM]${NC}"
  printf '%s\n' "$LARGE_FILE_LIST" | while IFS= read -r file; do
    [[ -z "$file" ]] && continue
    size=$(du -h "$file" 2>/dev/null | cut -f1 || echo "?")
    say "  $file ($size)"
  done
  say "Actions:"
  say "  • If accidental: remove + clean history if needed"
  say "  • If intentional: Git LFS or CDN/object storage"
  MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
else
  sayc "${GREEN}✓ No files larger than 10MB${NC}"
fi
say ""

# ============================================================
# CHECK 7: Debug/Test Files
# ============================================================

hr
sayc "${PURPLE}CHECK 7: Debug/Test Files${NC}"
hr

DEBUG_FILES=$(find . \( $(find_prune_args) \) -type f \( \
  -name "test.html" -o -name "debug.log" -o -name "*.swp" -o -name "*.swo" -o \
  -name ".DS_Store" -o -name "Thumbs.db" -o -name "phpinfo.php" -o -name "*.sql" \
\) -print 2>/dev/null || true)

if [[ -n "$DEBUG_FILES" ]]; then
  COUNT=$(printf '%s\n' "$DEBUG_FILES" | wc -l | tr -d ' ')
  sayc "${YELLOW}⚠️  Found $COUNT debug/test file(s) [HIGH]${NC}"
  printf '%s\n' "$DEBUG_FILES" | sed 's/^/  /'
  say "Actions:"
  say "  • Remove debug artifacts from repo"
  say "  • Add patterns to .gitignore"
  HIGH_ISSUES=$((HIGH_ISSUES + 1))
else
  sayc "${GREEN}✓ No debug/test files found${NC}"
fi
say ""

# ============================================================
# CHECK 8: Email/Phone in Output
# ============================================================

hr
sayc "${PURPLE}CHECK 8: Email/Phone Scraping Risk${NC}"
hr

if [[ "$SKIP_OUTPUT" -eq 1 || -z "${OUTPUT_DIR:-}" || ! -d "${OUTPUT_DIR:-}" ]]; then
  sayc "${BLUE}ℹ️  Skipping (no output dir or output scan disabled)${NC}"
  say ""
else
  EMAIL_COUNT=$(grep -roE "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}" "$OUTPUT_DIR" 2>/dev/null | wc -l | tr -d ' ' || true)
  PHONE_COUNT=$(grep -roE "\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}" "$OUTPUT_DIR" 2>/dev/null | wc -l | tr -d ' ' || true)

  if [[ ${EMAIL_COUNT:-0} -gt 0 || ${PHONE_COUNT:-0} -gt 0 ]]; then
    sayc "${BLUE}ℹ️  Contact info present in output:${NC}"
    [[ ${EMAIL_COUNT:-0} -gt 0 ]] && say "  • $EMAIL_COUNT email address(es)"
    [[ ${PHONE_COUNT:-0} -gt 0 ]] && say "  • $PHONE_COUNT phone number(s)"
    say "Actions:"
    say "  • If intentional: consider obfuscation or a contact form"
    say "  • If unintentional: remove and rebuild"
    LOW_ISSUES=$((LOW_ISSUES + 1))
  else
    sayc "${GREEN}✓ No email/phone numbers in output${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 9: Mixed Content
# ============================================================

hr
sayc "${PURPLE}CHECK 9: Mixed Content (HTTP/HTTPS)${NC}"
hr

if [[ "$SKIP_OUTPUT" -eq 1 || -z "${OUTPUT_DIR:-}" || ! -d "${OUTPUT_DIR:-}" ]]; then
  sayc "${BLUE}ℹ️  Skipping (no output dir or output scan disabled)${NC}"
  say ""
else
  HTTP_REFS=$(grep -roE "http://[^\"' ]+" "$OUTPUT_DIR" 2>/dev/null | grep -v "http://www.w3.org" | wc -l | tr -d ' ' || true)
  PROTO_RELATIVE=$(grep -roE "//[^\"' ]+\.(js|css|png|jpg|gif|svg|webp|woff|woff2)" "$OUTPUT_DIR" 2>/dev/null | wc -l | tr -d ' ' || true)

  if [[ ${HTTP_REFS:-0} -gt 0 ]]; then
    sayc "${YELLOW}⚠️  Found $HTTP_REFS http:// references [MEDIUM]${NC}"
    grep -roE "http://[^\"' ]+" "$OUTPUT_DIR" 2>/dev/null | grep -v "http://www.w3.org" | head -"$SHOW_MATCHES" | sed 's/^/  /' || true
    say "Actions:"
    say "  • Switch assets to https:// URLs"
    MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
  fi

  if [[ ${PROTO_RELATIVE:-0} -gt 0 ]]; then
    sayc "${BLUE}ℹ️  Found $PROTO_RELATIVE protocol-relative URLs (//...) [LOW]${NC}"
    say "Actions:"
    say "  • Prefer explicit https://"
    LOW_ISSUES=$((LOW_ISSUES + 1))
  fi

  if [[ ${HTTP_REFS:-0} -eq 0 && ${PROTO_RELATIVE:-0} -eq 0 ]]; then
    sayc "${GREEN}✓ No mixed content indicators found${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 10: Default/Demo Content
# ============================================================

hr
sayc "${PURPLE}CHECK 10: Default/Demo Content${NC}"
hr

if [[ "$SKIP_OUTPUT" -eq 1 || -z "${OUTPUT_DIR:-}" || ! -d "${OUTPUT_DIR:-}" ]]; then
  sayc "${BLUE}ℹ️  Skipping (no output dir or output scan disabled)${NC}"
  say ""
else
  DEMO_REFS=$(grep -rIEn \
    --include="*.html" --include="*.htm" --include="*.xml" --include="*.json" --include="*.txt" \
    "(example\.com|Your Name Here|Lorem ipsum|Demo Site|Test Site)" \
    "$OUTPUT_DIR" 2>/dev/null | wc -l | tr -d ' ' || true)

  if [[ ${DEMO_REFS:-0} -gt 0 ]]; then
    sayc "${YELLOW}⚠️  Found $DEMO_REFS placeholder reference(s) [LOW]${NC}"
    grep -rIEn \
      --include="*.html" --include="*.htm" --include="*.xml" --include="*.json" --include="*.txt" \
      "(example\.com|Your Name Here|Lorem ipsum|Demo Site|Test Site)" \
      "$OUTPUT_DIR" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /' || true
    say "Actions:"
    say "  • Replace placeholder content"
    LOW_ISSUES=$((LOW_ISSUES + 1))
  else
    sayc "${GREEN}✓ No obvious demo content found${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 11: .gitignore Coverage
# ============================================================

hr
sayc "${PURPLE}CHECK 11: .gitignore Configuration${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  if [[ -f ".gitignore" ]]; then
    REQUIRED_PATTERNS=(
      "*.bak"
      "*.backup*"
      ".env"
      "*.key"
      "*.pem"
      "*.log"
      ".DS_Store"
    )

    MISSING_PATTERNS=()
    for pattern in "${REQUIRED_PATTERNS[@]}"; do
      if ! grep -qF "$pattern" ".gitignore" 2>/dev/null; then
        MISSING_PATTERNS+=("$pattern")
      fi
    done

    if [[ ${#MISSING_PATTERNS[@]} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Missing recommended .gitignore patterns [LOW]${NC}"
      printf '  %s\n' "${MISSING_PATTERNS[@]}"
      say "Actions:"
      say "  • Add missing patterns"
      LOW_ISSUES=$((LOW_ISSUES + 1))
    else
      sayc "${GREEN}✓ .gitignore has good coverage${NC}"
    fi
  else
    sayc "${RED}✗ No .gitignore file found [MEDIUM]${NC}"
    say "Actions:"
    say "  • Create a .gitignore for secrets, build output, caches, OS files"
    MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
  fi
  say ""
fi

# ============================================================
# CHECK 12: Hardcoded Credentials in Common Code Dirs
# ============================================================

hr
sayc "${PURPLE}CHECK 12: Hardcoded Credentials in Code Dirs${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  HARDCODED_FOUND=0
  CODE_DIRS=("content" "layouts" "themes" "static" "src" "app" "lib" "pages")

  for d in "${CODE_DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    MATCHES=$(grep -riE "(password|api[_-]?key|secret|token)[[:space:]]*[:=][[:space:]]*['\"][^'\"]{8,}" "$d" \
      "${GREP_EXCLUDES[@]}" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${MATCHES:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Found $MATCHES potential credential(s) in $d/ [HIGH]${NC}"
      grep -riE "(password|api[_-]?key|secret|token)[[:space:]]*[:=][[:space:]]*['\"][^'\"]{8,}" "$d" \
        "${GREP_EXCLUDES[@]}" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /' || true
      HARDCODED_FOUND=$((HARDCODED_FOUND + MATCHES))
    fi
  done

  if [[ $HARDCODED_FOUND -gt 0 ]]; then
    say "Actions:"
    say "  • Replace hardcoded secrets with env vars"
    say "  • Rotate exposed values"
    HIGH_ISSUES=$((HIGH_ISSUES + 1))
  else
    sayc "${GREEN}✓ No obvious hardcoded secrets in common code dirs${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 13: Sensitive HTML Comments
# ============================================================

hr
sayc "${PURPLE}CHECK 13: Sensitive HTML Comments${NC}"
hr

if [[ "$SKIP_OUTPUT" -eq 1 || -z "${OUTPUT_DIR:-}" || ! -d "${OUTPUT_DIR:-}" ]]; then
  sayc "${BLUE}ℹ️  Skipping (no output dir or output scan disabled)${NC}"
  say ""
else
  DEV_COMMENTS=$(grep -rIEn --include="*.html" --include="*.htm" \
    "<!--.*\b(TODO|DEBUG|FIXME|XXX|HACK|password|token|key)\b" \
    "$OUTPUT_DIR" 2>/dev/null | wc -l | tr -d ' ' || true)

  if [[ ${DEV_COMMENTS:-0} -gt 0 ]]; then
    sayc "${YELLOW}⚠️  Found $DEV_COMMENTS development comment(s) in output HTML [LOW]${NC}"
    grep -rIEn --include="*.html" --include="*.htm" \
      "<!--.*\b(TODO|DEBUG|FIXME|XXX|HACK|password|token|key)\b" \
      "$OUTPUT_DIR" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /' || true
    say "Actions:"
    say "  • Remove sensitive comments before publishing"
    LOW_ISSUES=$((LOW_ISSUES + 1))
  else
    sayc "${GREEN}✓ No sensitive comments in output HTML${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 14: Security Headers in netlify.toml
# ============================================================

hr
sayc "${PURPLE}CHECK 14: Security Headers in netlify.toml${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  if [[ -f "netlify.toml" ]]; then
    SECURITY_HEADERS=("X-Frame-Options" "X-Content-Type-Options" "Content-Security-Policy" "Strict-Transport-Security" "Permissions-Policy" "Referrer-Policy")
    MISSING_HEADERS=()
    for header in "${SECURITY_HEADERS[@]}"; do
      if ! grep -qi "$header" "netlify.toml"; then
        MISSING_HEADERS+=("$header")
      fi
    done

    if [[ ${#MISSING_HEADERS[@]} -gt 0 ]]; then
      sayc "${BLUE}ℹ️  Missing recommended headers in netlify.toml [LOW]${NC}"
      printf '  %s\n' "${MISSING_HEADERS[@]}"
      say "Actions:"
      say "  • Add common security headers"
      LOW_ISSUES=$((LOW_ISSUES + 1))
    else
      sayc "${GREEN}✓ netlify.toml appears to include common security headers${NC}"
    fi
  else
    sayc "${BLUE}ℹ️  No netlify.toml found${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 15: Metadata/Identity Leaks
# ============================================================

hr
sayc "${PURPLE}CHECK 15: Metadata/Identity Leaks${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  IDENTITY_REFS=0

  if [[ -d ".git" ]]; then
    GIT_USER=$(git config user.name 2>/dev/null || echo "")
    GIT_EMAIL=$(git config user.email 2>/dev/null || echo "")

    if [[ -n "$GIT_USER" && "${GIT_USER,,}" != "oob" && "${GIT_USER,,}" != "oob skulden" ]]; then
      sayc "${BLUE}ℹ️  Git config name: $GIT_USER${NC}"
      say "Actions:"
      say "  • Consider per-repo identity:"
      say "      git config user.name \"Oob Skulden\""
      IDENTITY_REFS=$((IDENTITY_REFS + 1))
      LOW_ISSUES=$((LOW_ISSUES + 1))
    fi

    if [[ -n "$GIT_EMAIL" && "$GIT_EMAIL" != *"noreply"* ]]; then
      sayc "${BLUE}ℹ️  Git config email: $GIT_EMAIL${NC}"
      say "Actions:"
      say "  • Use GitHub noreply email for public repos"
      IDENTITY_REFS=$((IDENTITY_REFS + 1))
      LOW_ISSUES=$((LOW_ISSUES + 1))
    fi
  fi

  if [[ -d "content" ]]; then
    DRAFT_MARKERS=$(grep -riE "\[TODO\]|\[DRAFT\]|\[PLACEHOLDER\]" "content" "${GREP_EXCLUDES[@]}" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${DRAFT_MARKERS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Found $DRAFT_MARKERS draft marker(s) in content [LOW]${NC}"
      say "Actions:"
      say "  • Ensure drafts/placeholders aren’t published"
      LOW_ISSUES=$((LOW_ISSUES + 1))
      IDENTITY_REFS=$((IDENTITY_REFS + 1))
    fi
  fi

  if [[ $IDENTITY_REFS -eq 0 ]]; then
    sayc "${GREEN}✓ No obvious identity leaks detected${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 16: Dependency Vulnerabilities (npm audit)
# ============================================================

hr
sayc "${PURPLE}CHECK 16: Dependency Vulnerabilities (npm audit)${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  if [[ -f "package.json" ]]; then
    sayc "${BLUE}ℹ️  package.json found${NC}"
    if _has_cmd npm; then
      say "  Running npm audit (may take a moment)..."
      AUDIT_OUTPUT=$((npm audit --json 2>/dev/null) || echo '{"error": true}')
      if printf '%s' "$AUDIT_OUTPUT" | grep -q '"error"'; then
        sayc "${YELLOW}⚠️  npm audit had issues (deps may not be installed) [LOW]${NC}"
        say "Actions:"
        say "  • Run: npm ci then re-run audit"
        LOW_ISSUES=$((LOW_ISSUES + 1))
      else
        VULNS=$(printf '%s' "$AUDIT_OUTPUT" | grep -o '"total":[0-9]*' | head -1 | cut -d: -f2 || echo "0")
        if [[ ${VULNS:-0} -gt 0 ]]; then
          sayc "${YELLOW}⚠️  Found $VULNS vulnerability/vulnerabilities [MEDIUM]${NC}"
          say "Actions:"
          say "  • Upgrade dependencies / lockfile hygiene"
          MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
        else
          sayc "${GREEN}✓ No vulnerabilities reported by npm audit${NC}"
        fi
      fi
    else
      sayc "${BLUE}ℹ️  npm not installed — skipping${NC}"
    fi
  else
    sayc "${GREEN}✓ No package.json found${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 17: Git History Analysis (sensitive file extensions)
# ============================================================

hr
sayc "${PURPLE}CHECK 17: Git History Analysis${NC}"
hr
say ""

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  if [[ -d ".git" ]] && _has_cmd git; then
    SENSITIVE_HISTORY=$(
      git log --all --oneline --name-only 2>/dev/null \
        | grep -E '\.(env|key|pem|p12|pfx|backup|bak)$' \
        | wc -l | tr -d ' ' \
        || echo 0
    )

    if [[ "${SENSITIVE_HISTORY:-0}" -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Found $SENSITIVE_HISTORY sensitive-file reference(s) in git history [MEDIUM]${NC}"
      say "Actions:"
      say "  • Secrets may remain in history even if deleted"
      say "  • Use git filter-repo (preferred) or BFG"
      say "  • Rotate secrets anyway"
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    else
      sayc "${GREEN}✓ No obvious sensitive extensions in git history${NC}"
    fi
  else
    sayc "${BLUE}ℹ️  Not a git repository — skipping${NC}"
  fi
  say ""
fi


# ============================================================
# CHECK 18: Module/Theme Supply Chain
# ============================================================

hr
sayc "${PURPLE}CHECK 18: Module/Theme Supply Chain${NC}"
hr
say ""

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  if [[ -f "go.mod" ]]; then
    sayc "${BLUE}ℹ️  go.mod found (Hugo modules possible)${NC}"
    NON_OFFICIAL=$(
      grep -E "github\.com/[^/]+/[^/]+" "go.mod" 2>/dev/null \
        | grep -vi "gohugoio" \
        | wc -l | tr -d ' ' \
        || echo 0
    )

    if [[ "${NON_OFFICIAL:-0}" -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Found $NON_OFFICIAL third-party module(s) [MEDIUM]${NC}"
      grep -E "github\.com/[^/]+/[^/]+" "go.mod" 2>/dev/null \
        | grep -vi "gohugoio" \
        | head -"$SHOW_MATCHES" \
        | sed 's/^/  /'
      say "Actions:"
      say "  • Pin versions; review upstream repos"
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    else
      sayc "${GREEN}✓ No obvious third-party modules in go.mod${NC}"
    fi
    say ""
  fi

  if [[ -d "themes" ]]; then
    # Avoid iterating literal "themes/*" when empty
    if ! compgen -G "themes/*" >/dev/null; then
      sayc "${GREEN}✓ No themes detected${NC}"
      say ""
    else
      THEME_COUNT=$(find "themes" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ' || echo 0)
      sayc "${BLUE}ℹ️  Found ${THEME_COUNT:-0} theme(s)${NC}"

      for theme_dir in themes/*; do
        [[ -d "$theme_dir" ]] || continue
        theme_name=$(basename "$theme_dir")

        # ✅ FIX: run _has_cmd outside [[ ]]
        if [[ -d "$theme_dir/.git" ]] && _has_cmd git; then
          REMOTE=$(cd "$theme_dir" && git remote get-url origin 2>/dev/null || echo "unknown")
          sayc "  ${GREEN}✓${NC} $theme_name: git-tracked ($REMOTE)"

          LICENSE_FILE=""
          [[ -f "$theme_dir/LICENSE" ]] && LICENSE_FILE="$theme_dir/LICENSE"
          [[ -f "$theme_dir/LICENSE.md" ]] && LICENSE_FILE="$theme_dir/LICENSE.md"

          if [[ -n "$LICENSE_FILE" ]]; then
            LICENSE_TYPE=$(grep -iE "(MIT|Apache|GPL|BSD)" "$LICENSE_FILE" 2>/dev/null | head -1 || echo "Unknown")
            if printf '%s' "$LICENSE_TYPE" | grep -qi "GPL"; then
              sayc "    ${YELLOW}⚠️${NC} GPL-ish license detected [LOW]"
              LOW_ISSUES=$((LOW_ISSUES + 1))
            else
              sayc "    ${GREEN}✓${NC} License hint: $LICENSE_TYPE"
            fi
          else
            sayc "    ${YELLOW}⚠️${NC} No LICENSE file found [LOW]"
            LOW_ISSUES=$((LOW_ISSUES + 1))
          fi
        else
          sayc "  ${YELLOW}⚠️${NC} $theme_name: copied theme (no version tracking) [MEDIUM]"
          say "    Actions: prefer submodule or Hugo module tracking"
          MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
        fi
      done
      say ""
    fi
  else
    sayc "${GREEN}✓ No themes directory found${NC}"
    say ""
  fi
fi

# ============================================================
# CHECK 19: Custom Shortcode Security (Hugo)
# ============================================================

hr
sayc "${PURPLE}CHECK 19: Custom Shortcode Injection Risks${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  if [[ -d "layouts/shortcodes" ]]; then
    SHORTCODE_COUNT=$(find "layouts/shortcodes" -name "*.html" 2>/dev/null | wc -l | tr -d ' ')
    if [[ ${SHORTCODE_COUNT:-0} -gt 0 ]]; then
      sayc "${BLUE}ℹ️  Found $SHORTCODE_COUNT custom shortcode(s)${NC}"
      UNSAFE=$(grep -rE "(\.Get|\.Inner|readFile|getJSON|getCSV)" "layouts/shortcodes" --include="*.html" 2>/dev/null | wc -l | tr -d ' ' || true)
      if [[ ${UNSAFE:-0} -gt 0 ]]; then
        sayc "${YELLOW}⚠️  Found $UNSAFE dynamic shortcode usage(s) [MEDIUM]${NC}"
        grep -rE "(\.Get|\.Inner|readFile|getJSON|getCSV)" "layouts/shortcodes" --include="*.html" -n 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
        say "Actions:"
        say "  • Avoid rendering untrusted input directly"
        MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
      else
        sayc "${GREEN}✓ Shortcodes appear safe${NC}"
      fi
    else
      sayc "${GREEN}✓ No shortcodes found${NC}"
    fi
  else
    sayc "${GREEN}✓ No custom shortcodes directory found${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 20: Netlify Build Logs / Env Leaks
# ============================================================

hr
sayc "${PURPLE}CHECK 20: Netlify Build Env Exposure${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  if [[ -f "netlify.toml" ]]; then
    ECHO_COMMANDS=$(grep -E "(echo|print|console\.log).*\\\$" "netlify.toml" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${ECHO_COMMANDS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Build commands may leak env vars [HIGH]${NC}"
      grep -E "(echo|print|console\.log).*\\\$" "netlify.toml" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
      say "Actions:"
      say "  • Remove echo/print of env vars in build steps"
      HIGH_ISSUES=$((HIGH_ISSUES + 1))
    else
      sayc "${GREEN}✓ No obvious env-var echoing in netlify.toml${NC}"
    fi

    if ! grep -qiE 'publish[[:space:]]*=' "netlify.toml"; then
      sayc "${YELLOW}⚠️  Publish dir not explicitly set [LOW]${NC}"
      say "Actions:"
      say "  • Set publish directory explicitly"
      LOW_ISSUES=$((LOW_ISSUES + 1))
    fi
  else
    sayc "${GREEN}✓ No netlify.toml found${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 21: RSS/Sitemap Unintended Disclosure
# ============================================================

hr
sayc "${PURPLE}CHECK 21: RSS/Sitemap Information Leaks${NC}"
hr

if [[ "$SKIP_OUTPUT" -eq 1 || -z "${OUTPUT_DIR:-}" || ! -d "${OUTPUT_DIR:-}" ]]; then
  sayc "${BLUE}ℹ️  Skipping (no output dir or output scan disabled)${NC}"
  say ""
else
  RSS_SITEMAP_ISSUES=0

  if [[ -f "$OUTPUT_DIR/index.xml" ]]; then
    DRAFT_IN_RSS=$(grep -i "draft" "$OUTPUT_DIR/index.xml" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${DRAFT_IN_RSS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  RSS feed may include draft markers [HIGH]${NC}"
      say "Actions:"
      say "  • Ensure drafts excluded in prod builds"
      HIGH_ISSUES=$((HIGH_ISSUES + 1))
      RSS_SITEMAP_ISSUES=$((RSS_SITEMAP_ISSUES + 1))
    fi
  fi

  if [[ -f "$OUTPUT_DIR/sitemap.xml" ]]; then
    SENSITIVE_PATHS=$(grep -E "(admin|private|internal|test|staging)" "$OUTPUT_DIR/sitemap.xml" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${SENSITIVE_PATHS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Sitemap includes sensitive-looking paths [MEDIUM]${NC}"
      grep -E "(admin|private|internal|test|staging)" "$OUTPUT_DIR/sitemap.xml" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
      say "Actions:"
      say "  • Remove sensitive paths from sitemap"
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
      RSS_SITEMAP_ISSUES=$((RSS_SITEMAP_ISSUES + 1))
    fi
  fi

  if [[ $RSS_SITEMAP_ISSUES -eq 0 ]]; then
    sayc "${GREEN}✓ RSS and sitemap look clean${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 22: Front Matter Secrets
# ============================================================

hr
sayc "${PURPLE}CHECK 22: Front Matter Secrets${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  if [[ -d "content" ]]; then
    FRONTMATTER_SECRETS=$(grep -rE "^(api_key|apikey|token|secret|password):[[:space:]]*['\"]?[A-Za-z0-9._-]{20,}" "content" --include="*.md" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${FRONTMATTER_SECRETS:-0} -gt 0 ]]; then
      sayc "${RED}✗ Found $FRONTMATTER_SECRETS potential secret(s) in front matter [CRITICAL]${NC}"
      grep -rE "^(api_key|apikey|token|secret|password):" "content" --include="*.md" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
      say "Actions:"
      say "  • Remove secret values from front matter"
      say "  • Rotate tokens/keys"
      CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
    else
      sayc "${GREEN}✓ No obvious secrets in content front matter${NC}"
    fi
  else
    sayc "${BLUE}ℹ️  No content/ directory found${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 23: Git Hooks / Pre-commit Validation
# ============================================================

hr
sayc "${PURPLE}CHECK 23: Pre-commit Hooks / Validation${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  if [[ -d ".git/hooks" ]]; then
    HAS_ANY=0
    if [[ -f ".git/hooks/pre-commit" ]]; then
      HAS_ANY=1
      sayc "${GREEN}✓ .git/hooks/pre-commit exists${NC}"
      if grep -qiE "(secret|credential|key|token|trufflehog|gitleaks|detect-secrets)" ".git/hooks/pre-commit" 2>/dev/null; then
        sayc "${GREEN}✓ Pre-commit includes security keywords${NC}"
      else
        sayc "${YELLOW}⚠️  Pre-commit exists but no secret scanning detected [LOW]${NC}"
        LOW_ISSUES=$((LOW_ISSUES + 1))
      fi
    fi

    if [[ -f ".pre-commit-config.yaml" ]]; then
      HAS_ANY=1
      sayc "${GREEN}✓ .pre-commit-config.yaml found${NC}"
      if grep -qiE "(trufflehog|gitleaks|detect-secrets|secret)" ".pre-commit-config.yaml" 2>/dev/null; then
        sayc "${GREEN}✓ Pre-commit config includes security hooks${NC}"
      else
        sayc "${YELLOW}⚠️  Pre-commit config missing secrets hooks [LOW]${NC}"
        LOW_ISSUES=$((LOW_ISSUES + 1))
      fi
    fi

    if [[ $HAS_ANY -eq 0 ]]; then
      sayc "${YELLOW}⚠️  No pre-commit hooks configured [MEDIUM]${NC}"
      say "Actions:"
      say "  • Add pre-commit with at least secrets scanning + lint"
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    fi
  else
    sayc "${BLUE}ℹ️  No .git/hooks directory found${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 24: Output directory committed (hygiene)
# ============================================================

hr
sayc "${PURPLE}CHECK 24: Output Directory Committed (Build Artifact Hygiene)${NC}"
hr

if [[ -d ".git" && -n "${OUTPUT_DIR:-}" && -d "${OUTPUT_DIR:-}" && "$ONLY_OUTPUT" -eq 0 ]]; then
  if [[ "$INCLUDE_OUTPUT_IN_SOURCE" -eq 0 ]]; then
    if _has_cmd git; then
      OUTPUT_TRACKED_COUNT=$(git ls-files "$OUTPUT_BASENAME" 2>/dev/null | wc -l | tr -d ' ' || true)
      if [[ ${OUTPUT_TRACKED_COUNT:-0} -gt 0 ]]; then
        sayc "${YELLOW}⚠️  Output dir '$OUTPUT_BASENAME/' appears tracked by git [HIGH]${NC}"
        say "Actions:"
        say "  • Usually do NOT commit build output for Netlify builds"
        say "  • Remove tracked output:"
        say "      git rm -r --cached \"$OUTPUT_BASENAME\""
        say "      echo \"$OUTPUT_BASENAME/\" >> .gitignore"
        HIGH_ISSUES=$((HIGH_ISSUES + 1))
      else
        sayc "${GREEN}✓ Output dir '$OUTPUT_BASENAME/' is not tracked by git${NC}"
      fi
    else
      sayc "${BLUE}ℹ️  git not installed — cannot check tracked output${NC}"
    fi
  else
    sayc "${BLUE}ℹ️  Output tracking allowed (--include-output-in-source)${NC}"
  fi
else
  sayc "${BLUE}ℹ️  Not applicable (no git repo or no output dir detected)${NC}"
fi
say ""

# ============================================================
# FINAL SUMMARY
# ============================================================

say "=============================================="
say "🔒 FINAL SECURITY SUMMARY 🔒"
say "=============================================="
say ""
say "Generator detected: $GENERATOR"
[[ -n "${OUTPUT_DIR:-}" ]] && say "Output dir detected: $OUTPUT_DIR"
say ""

TOTAL_ISSUES=$((CRITICAL_ISSUES + HIGH_ISSUES + MEDIUM_ISSUES + LOW_ISSUES))

if [[ $CRITICAL_ISSUES -gt 0 ]]; then
  sayc "${RED}🚨 CRITICAL: $CRITICAL_ISSUES issue(s) - FIX IMMEDIATELY${NC}"
fi
if [[ $HIGH_ISSUES -gt 0 ]]; then
  sayc "${RED}⚠️  HIGH:     $HIGH_ISSUES issue(s) - Fix soon${NC}"
fi
if [[ $MEDIUM_ISSUES -gt 0 ]]; then
  sayc "${YELLOW}⚠️  MEDIUM:   $MEDIUM_ISSUES issue(s) - Address when possible${NC}"
fi
if [[ $LOW_ISSUES -gt 0 ]]; then
  sayc "${BLUE}ℹ️  LOW:      $LOW_ISSUES issue(s) - Nice to fix${NC}"
fi

say ""
if [[ $TOTAL_ISSUES -eq 0 ]]; then
  sayc "${GREEN}✅ EXCELLENT! No security issues found!${NC}"
  say ""
  sayc "${PURPLE}🦛 Published by Oob Skulden™ — stay vigilant, stay submerged.${NC}"
else
  sayc "${YELLOW}⚠️  Found $TOTAL_ISSUES total security issue(s)${NC}"
  say ""
  say "Priority actions (in order):"
  [[ $CRITICAL_ISSUES -gt 0 ]] && say "  1. 🚨 Fix CRITICAL issues immediately"
  [[ $HIGH_ISSUES -gt 0 ]] && say "  2. ⚠️  Address HIGH priority issues"
  [[ $MEDIUM_ISSUES -gt 0 ]] && say "  3. ⚠️  Review MEDIUM priority issues"
  [[ $LOW_ISSUES -gt 0 ]] && say "  4. ℹ️  Consider LOW priority improvements"
fi

say ""
say "=============================================="
sayc "${PURPLE}Generated by: 🦛 Published by Oob Skulden™ 🦛${NC}"
sayc "${PURPLE}\"The threats you don't see coming\"${NC}"
say "=============================================="
say ""

if [[ $CRITICAL_ISSUES -gt 0 ]]; then
  exit 3
elif [[ $HIGH_ISSUES -gt 0 ]]; then
  exit 2
elif [[ $MEDIUM_ISSUES -gt 0 ]]; then
  exit 1
else
  exit 0
fi
