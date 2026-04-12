#!/bin/bash
# Copyright 2026 Morravex
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# --- SentinelClaw v0.0.1: Sentinel Setup ---
# One Command. Total Security. 🛡️

set -e

# Clear screen for premium feel
clear

echo "🛡️  SentinelClaw v0.0.1: Sentinel Security Appliance Setup"
echo "------------------------------------------------------"

# 0. Root check for /opt/sentinel installation
SENTINEL_ROOT="/opt/sentinel"
if [ "$(id -u)" -ne 0 ]; then
    echo "❌ ERROR: setup.sh must run as root (sudo ./setup.sh)"
    echo "   Sentinel shims are installed to $SENTINEL_ROOT (root-owned, agent-proof)."
    echo "   The sentinel binary and runtime data stay in your project directory."
    exit 1
fi
echo "✅ Running as root — shims will be installed to $SENTINEL_ROOT (protected from agents)."

# 1. Docker-Only Check
echo "🔍 Checking Docker Readiness..."
check_dep() {
    if ! command -v $1 &> /dev/null; then
        echo "   ❌ Dependency Missing: $1. Please install it to proceed."
        exit 1
    else
        echo "   ✅ $1 found."
    fi
}
check_dep "docker"
check_dep "docker-compose"

# 2. Interactive Authority Setup
echo ""
echo "📱 Sentinel Mission Control (Telegram Bridge)"
echo "---------------------------------------------"
echo "Recommended: Remote command approvals via your Sentinel app."
read -p "👉 Enable Telegram? [y/N]: " USE_TELEGRAM

TG_TOKEN="your_bot_token"
TG_CHAT="your_chat_id"

if [[ $USE_TELEGRAM =~ ^[Yy]$ ]]; then
    read -p "   👉 Enter Bot Token (from @BotFather): " TG_TOKEN
    read -p "   👉 Enter Chat ID (from @userinfobot): " TG_CHAT
fi

echo "📝 Initializing Sentinel Authority Vault (.env)..."
cat <<EOF > .env
# --- SENTINEL AUTHORITY KEYS ---
TELEGRAM_BOT_TOKEN=$TG_TOKEN
TELEGRAM_CHAT_ID=$TG_CHAT
SENTINEL_PAIRING_KEY=$(openssl rand -hex 16 2>/dev/null || od -An -N16 -x /dev/urandom | tr -d ' ')
EOF
echo "   ✅ Sentinel .env created."

# 2.1 Agent Vault-Mesh (8080-8089)
echo "📦 Initializing Agent Isolation Mesh..."
AGENTS=("openclaw" "hermes" "aider" "autogpt" "babyagi" "gpthinker" "meta" "mistral" "devin" "default")
for agent in "${AGENTS[@]}"; do
    if [ ! -f ".env-$agent" ]; then
        cat <<EOF > ".env-$agent"
# --- SECRETS FOR AGENT: $agent ---
OPENROUTER_API_KEY=sk-or-v1-placeholder
OPENAI_API_KEY=sk-placeholder
EOF
    fi
done
touch sentinel.db # Ensure persistent database exists for first mount
echo "   ✅ 10 Isolation Vaults & Persistent SQL Storage Initialized."

# 3. Docker Launch (Zero-Install Build)
echo "🐳 Deploying Sentinel Security Appliance via Docker..."
touch sentinel.db # Ensure it's a file on host before mounting

# Copy example config if no sentinel.toml exists
if [ ! -f sentinel.toml ] && [ -f sentinel.toml.example ]; then
    cp sentinel.toml.example sentinel.toml
    echo "   ✅ Created sentinel.toml from example template."
fi
docker-compose up -d --build

# Wait for readiness
echo "⏳ Waiting for Sentinel Identity Mesh to stabilize..."
for i in {1..10}; do
    if curl -s http://localhost:8080/health | grep -q "sentinel"; then
        echo "   ✅ Sentinel v0.0.1 is ACTIVE."
        break
    fi
    sleep 2
done

# 4. Generate Sentinel Shims (Direct-to-Hypervisor)
# Shims go to /opt/sentinel/shims — root-owned, outside /home, agent-proof.
mkdir -p "$SENTINEL_ROOT/shims"
echo "🛰️  Generating Sentinel Shims → $SENTINEL_ROOT/shims/ (Comprehensive Runtime Coverage)..."
SENTINEL_BIN="$(pwd)/target/release/sentinel"

create_shim() {
    local cmd=$1
    # We use a smart shim that detects if it's already inside a Sentinel cage
    cat <<EOF > "$SENTINEL_ROOT/shims/$cmd"
#!/bin/bash
if [ "\$SENTINEL_ACTIVE" = "1" ]; then
    # Already in the cage, execute the real binary
    # We bypass the shims by temporarily removing them from PATH
    REAL_PATH=\$(PATH=\$(echo "\$PATH" | sed -e "s|$SHIMS_PATH:||g" -e "s|:\$SHIMS_PATH||g") which "$cmd")
    exec "\$REAL_PATH" "\$@"
else
    # Not in the cage, enter it
    exec "$SENTINEL_BIN" run "$cmd" "\$@"
fi
EOF
    chmod +x "$SENTINEL_ROOT/shims/$cmd"
}

# Expanded list of runtimes and tools for system-wide coverage
RUNTIMES=(
    # Languages
    "python" "python3" "node" "bun" "deno" "perl" "ruby" "go" "rustc" "java" "php" "lua" "javac"
    # Package Managers
    "pip" "pip3" "npm" "pnpm" "yarn" "cargo" "gem" "composer" "uv" "uvx"
    # System & Dev Tools
    "bash" "sh" "zsh" "curl" "wget" "git" "docker" "docker-compose" "make" "gcc" "g++" "clang" "xargs"
    # Cloud & Infrastructure
    "aws" "gcloud" "terraform" "kubectl" "heroku" "ansible"
)

for rt in "${RUNTIMES[@]}"; do
    create_shim "$rt"
done
# Lock shims directory — root:root 755, agent cannot modify or delete
chown -R root:root "$SENTINEL_ROOT/shims"
chmod -R 755 "$SENTINEL_ROOT/shims"
echo "   ✅ Shims locked: root:root 755 at $SENTINEL_ROOT/shims/"

echo "   ✅ System-Wide Secret Materialization Mesh Ready."

# 5. Global Path Injection (Automation)
echo "💉 Injecting Sentinel Mesh into Shell Profile..."
SHIMS_PATH="$SENTINEL_ROOT/shims"
LINE="export PATH=\"$SHIMS_PATH:\$PATH\""

update_profile() {
    local profile=$1
    if [ -f "$profile" ]; then
        if ! grep -q "$SHIMS_PATH" "$profile"; then
            echo "" >> "$profile"
            echo "# --- SENTINEL CLAW SHIMS [BEGIN] ---" >> "$profile"
            echo "# Managed by sentinel-claw-v2 setup.sh — do not edit between markers" >> "$profile"
            echo "$LINE" >> "$profile"
            echo "# --- SENTINEL CLAW SHIMS [END] ---" >> "$profile"
            echo "   ✅ Path injected into $profile"
        else
            echo "   ℹ️  Sentinel path already exists in $profile"
        fi
    fi
}

update_profile "$HOME/.bashrc"
update_profile "$HOME/.zshrc"
update_profile "$HOME/.profile"

# 6. Final Onboarding & Dashboard Access
echo ""
echo "🚀 Sentinel is now ARMED and ACTIVE."
echo "------------------------------------------------------"
echo "🌐 ACCESS DASHBOARD: http://localhost:3333"

# Open Dashboard Automatically (Cross-Platform)
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if command -v xdg-open &> /dev/null; then xdg-open http://localhost:3333 &> /dev/null; fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    open http://localhost:3333 &> /dev/null
fi

echo ""
echo "🛡️  ALL RUNTIMES (python, git, curl) are now PROTECTED via shims."
echo "Sentinel has automatically injected its path into your shell profile."
echo "Please restart your terminal or run: source ~/.bashrc"
echo ""
echo "📱 Mission Control initialized on Telegram bot."
echo "------------------------------------------------------------"
echo "🛡️  Sentinel Identity. Global Integration. Zero Trace."
echo ""
echo "📡 Entering Live Audit Monitor (Ctrl+C to exit setup)..."
docker-compose logs -f
