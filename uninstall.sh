#!/bin/bash
# =============================================================================
# SentinelClaw v0.0.1: Secure Uninstall Script
# =============================================================================
#
# SECURITY DESIGN
# ---------------
# This script is the ONLY authorized method to remove sentinel-claw-v2.
# It is intentionally designed to be AI/agent-proof through multiple layers:
#
# 1. INTERACTIVE-ONLY: All confirmation prompts read from /dev/tty, not stdin.
#    Agents cannot pipe "y" or automate responses. Only a human at a keyboard
#    can answer the confirmation prompt.
#
# 2. NO CLI FLAGS: The script rejects ALL arguments. There is no --yes, --force,
#    --silent, or any programmatic bypass. An agent cannot trigger silent mode.
#
# 3. PROCESS TREE VALIDATION: The script walks the entire parent PID (PPid)
#    chain up to PID 1, checking every ancestor against a list of known sentinel
#    process names. If ANY ancestor is a sentinel process, the script aborts.
#    This prevents sentinel from spawning this uninstaller to self-destruct.
#
# 4. AUDIT TRAIL: Every uninstall attempt is logged to sentinel's audit log
#    with timestamp, user, and outcome (attempted/completed/aborted).
#
# 5. TELEGRAM NOTIFICATION: If a Telegram bot is configured, a final alert is
#    sent before removal so the human operator knows uninstall occurred.
#
# 6. BRACKETED MARKERS: Shell profile cleanup uses unique bracketed markers
#    (# --- SENTINEL CLAW SHIMS [BEGIN] --- / # --- SENTINEL CLAW SHIMS [END] ---)
#    that are only written by setup.sh. This prevents accidental or malicious
#    removal of unrelated PATH entries.
#
# USAGE:  ./uninstall.sh
#         (no arguments accepted)
# =============================================================================
set -euo pipefail

# --- Configuration ---
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUDIT_LOG="${PROJECT_DIR}/sentinel-audit.log"
SENTINEL_ROOT="/opt/sentinel"
SHELL_MARKER_BEGIN="# --- SENTINEL CLAW SHIMS [BEGIN] ---"
SHELL_MARKER_END="# --- SENTINEL CLAW SHIMS [END] ---"
SENTINEL_NAMES="sentinel sentinel-gateway sentinel-claw sentinel_monitor"

# =============================================================================
# LAYER 1: Reject ALL arguments (no --yes, --force, etc.)
# =============================================================================
if [ $# -gt 0 ]; then
    echo "❌ ERROR: This script does not accept any arguments."
    echo "   Run './uninstall.sh' with no flags to proceed."
    echo "   (This is a security measure — there is no silent mode.)"
    exit 1
fi

# =============================================================================
# LAYER 2: Process tree validation — ensure we are NOT spawned by sentinel
# =============================================================================
check_process_tree() {
    local pid=$$
    local depth=0
    local max_depth=50

    echo "🔍 Validating process tree (ensuring sentinel is not our ancestor)..."

    while [ "$pid" -gt 1 ] && [ "$depth" -lt "$max_depth" ]; do
        # Get parent PID
        local ppid
        ppid=$(awk '{print $4}' "/proc/${pid}/stat" 2>/dev/null) || break

        if [ -z "$ppid" ] || [ "$ppid" -le 1 ]; then
            break
        fi

        # Get parent process name
        local pname
        pname=$(awk -F'\0' '{print $1}' "/proc/${ppid}/cmdline" 2>/dev/null | awk '{print $1}' | xargs basename 2>/dev/null) || pname=""

        # Check against known sentinel process names
        for sentinel_name in $SENTINEL_NAMES; do
            if echo "$pname" | grep -qi "$sentinel_name"; then
                echo "❌ SECURITY ABORT: Parent process '${pname}' (PID ${ppid}) is a sentinel process."
                echo "   This uninstall script cannot be run from within sentinel's process tree."
                echo "   Please open a new terminal and run './uninstall.sh' directly."
                log_audit "ABORTED" "Spawned by sentinel process: ${pname} (PID ${ppid})"
                exit 1
            fi
        done

        pid=$ppid
        depth=$((depth + 1))
    done

    echo "   ✅ Process tree clean — not spawned by sentinel."
}

# =============================================================================
# LAYER 3: Audit logging
# =============================================================================
log_audit() {
    local status="$1"
    local detail="${2:-}"
    local timestamp
    timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    local user
    user=$(whoami)
    local tty
    tty=$(tty 2>/dev/null || echo "no-tty")

    mkdir -p "$(dirname "$AUDIT_LOG")"
    echo "[${timestamp}] UNINSTALL ${status} | user=${user} tty=${tty} | ${detail}" >> "$AUDIT_LOG"
}

# =============================================================================
# LAYER 4: Interactive human confirmation (reads from /dev/tty)
# =============================================================================
confirm_uninstall() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║          🛡️  SentinelClaw v0.0.1 — UNINSTALL               ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║  This will PERMANENTLY remove:                              ║"
    echo "║    • Sentinel shims from PATH (~/.bashrc, ~/.zshrc, ...)   ║"
    echo "║    • Shims directory: ${SENTINEL_ROOT}/shims/ (root-owned)  "
    echo "║    • Sentinel Docker services (sentinel-gateway)            ║"
    echo "║                                                             ║"
    echo "║  ⚠️  Your .env files and sentinel.db will be PRESERVED.     ║"
    echo "║     (Delete them manually if you want a clean slate.)       ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""

    # Read from /dev/tty — agents cannot answer this
    if [ ! -t 0 ] || [ ! -e /dev/tty ]; then
        echo "❌ ERROR: No interactive terminal detected."
        echo "   This script requires a human at a keyboard."
        echo "   (Agents cannot automate this confirmation.)"
        log_audit "ABORTED" "No interactive TTY available"
        exit 1
    fi

    printf "⚠️  Type 'yes-uninstall-sentinel' to proceed: "
    local response
    read -r response < /dev/tty

    if [ "$response" != "yes-uninstall-sentinel" ]; then
        echo ""
        echo "❌ Uninstall cancelled. (Exact phrase required — no shortcuts.)"
        log_audit "CANCELLED" "User declined confirmation"
        exit 0
    fi

    echo ""
    echo "✅ Confirmation received. Proceeding with uninstall..."
}

# =============================================================================
# LAYER 5: Telegram notification (if bot is configured)
# =============================================================================
notify_telegram() {
    local env_file="${PROJECT_DIR}/.env"
    if [ ! -f "$env_file" ]; then
        return
    fi

    # Source safely — only extract the two vars we need
    local bot_token chat_id
    bot_token=$(grep -oP '^TELEGRAM_BOT_TOKEN=\K.*' "$env_file" 2>/dev/null || true)
    chat_id=$(grep -oP '^TELEGRAM_CHAT_ID=\K.*' "$env_file" 2>/dev/null || true)

    if [ -z "$bot_token" ] || [ -z "$chat_id" ] || [ "$bot_token" = "***" ]; then
        return
    fi

    local hostname
    hostname=$(hostname 2>/dev/null || echo "unknown")
    local message="🛡️ SENTINEL UNINSTALL ALERT%0A%0AHost: ${hostname}%0AUser: $(whoami)%0ATime: $(date -u '+%Y-%m-%d %H:%M:%S UTC')%0A%0ASentinelClaw v0.0.1 has been uninstalled by a human operator."

    curl -s -m 10 "https://api.telegram.org/bot${bot_token}/sendMessage" \
        -d "chat_id=${chat_id}" \
        -d "text=${message}" \
        -d "parse_mode=HTML" \
        >/dev/null 2>&1 || true

    echo "   📱 Telegram notification sent."
}

# =============================================================================
# STEP 1: Clean shell profiles (bracketed marker removal)
# =============================================================================
clean_shell_profiles() {
    echo "🧹 Cleaning shell profiles..."

    local profiles=(
        "$HOME/.bashrc"
        "$HOME/.zshrc"
        "$HOME/.profile"
    )

    for profile in "${profiles[@]}"; do
        if [ ! -f "$profile" ]; then
            continue
        fi

        # Check if our bracketed markers exist
        if grep -q "$SHELL_MARKER_BEGIN" "$profile" 2>/dev/null; then
            # Remove everything between BEGIN and END markers (inclusive)
            # Use a temp file for safety
            local tmp="${profile}.sentinel-uninstall-tmp"
            awk -v begin="$SHELL_MARKER_BEGIN" -v end="$SHELL_MARKER_END" '
                BEGIN { skip=0 }
                $0 ~ begin { skip=1; next }
                $0 ~ end { skip=0; next }
                skip == 0 { print }
            ' "$profile" > "$tmp"

            # Clean up any double blank lines left behind
            cat -s "$tmp" > "$profile"
            rm -f "$tmp"

            echo "   ✅ Removed sentinel PATH from: $profile"
        else
            # Legacy marker fallback (from old setup.sh without brackets)
            if grep -q "# --- SENTINEL CLAW AUTOMATIC SHIMS ---" "$profile" 2>/dev/null; then
                local tmp="${profile}.sentinel-uninstall-tmp"
                grep -v "SENTINEL CLAW AUTOMATIC SHIMS" "$profile" | \
                grep -v "$(echo "$PROJECT_DIR" | sed 's/[^^]/[&]/g; s/\^/\\^/g')" > "$tmp" || true
                cat -s "$tmp" > "$profile"
                rm -f "$tmp"
                echo "   ✅ Removed legacy sentinel PATH from: $profile"
            else
                echo "   ℹ️  No sentinel entries found in: $profile"
            fi
        fi
    done
}

# =============================================================================
# STEP 2: Remove shims directory
# =============================================================================
remove_shims() {
    echo "🗑️  Removing shims directory..."
    local shims_dir="${SENTINEL_ROOT}/shims"

    if [ -d "$shims_dir" ]; then
        # Shims are root-owned — need sudo to remove
        if [ "$(id -u)" -ne 0 ]; then
            echo "   ⚠️  Shims are root-owned at $shims_dir"
            echo "   Run: sudo rm -rf $shims_dir"
            return 1
        fi
        rm -rf "$shims_dir"
        echo "   ✅ Removed: $shims_dir"
    else
        echo "   ℹ️  Shims directory not found (already removed)."
    fi
}

# =============================================================================
# STEP 3: Stop sentinel Docker services
# =============================================================================
stop_services() {
    echo "🛑 Stopping sentinel Docker services..."

    local compose_file="${PROJECT_DIR}/docker-compose.yml"
    if [ ! -f "$compose_file" ]; then
        echo "   ℹ️  No docker-compose.yml found, skipping."
        return
    fi

    # Check if docker is available
    if ! command -v docker-compose &>/dev/null && ! command -v docker &>/dev/null; then
        echo "   ℹ️  Docker not available, skipping service stop."
        return
    fi

    cd "$PROJECT_DIR"
    if command -v docker-compose &>/dev/null; then
        docker-compose down 2>/dev/null || true
    else
        docker compose down 2>/dev/null || true
    fi
    echo "   ✅ Sentinel services stopped."
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================
main() {
    echo ""
    echo "🛡️  SentinelClaw Uninstall — Security-Hardened Remover"
    echo "======================================================"
    echo ""

    # Security validations
    check_process_tree

    # Log the attempt
    log_audit "ATTEMPTED" "Uninstall initiated by $(whoami) on $(tty)"

    # Interactive confirmation (must come from human)
    confirm_uninstall

    # Log confirmed
    log_audit "CONFIRMED" "User confirmed uninstall"

    # Send Telegram notification BEFORE removal
    echo ""
    echo "📱 Sending final notification..."
    notify_telegram

    # Perform uninstall steps
    echo ""
    clean_shell_profiles
    echo ""
    remove_shims
    echo ""
    stop_services

    # Final audit log
    log_audit "COMPLETED" "Sentinel uninstalled successfully"

    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  ✅  SentinelClaw v0.0.1 has been uninstalled.              ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║  Preserved (delete manually if desired):                    ║"
    echo "║    • ${PROJECT_DIR}/.env                                     "
    echo "║    • ${PROJECT_DIR}/.env-*                                   "
    echo "║    • ${PROJECT_DIR}/sentinel.db                              "
    echo "║    • ${PROJECT_DIR}/sentinel.toml                            "
    echo "║                                                             ║"
    echo "║  Audit log: ${AUDIT_LOG}                                     "
    echo "║                                                             ║"
    echo "║  Please restart your terminal or run: source ~/.bashrc      ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
}

main "$@"
