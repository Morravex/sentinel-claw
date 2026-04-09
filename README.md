# 🛡️ SentinelClaw: The Definitive Security Layer for the Agentic Stack

**Unified Sovereign Proxy & Hardened Environment Guardian for Autonomous Agents.**

---

### 🌐 Secure the Autonomous Frontier
As AI agents move from "chatting" to "executing," they become the most sensitive surface in your infrastructure. **SentinelClaw** is the definitive security gateway that isolates agents from raw credentials, redacts PII in real-time, and enforces kernel-level governance.

It transforms your agents into **"Secret-Blind" entities**—they operate on stable, cryptographically secure **Ghost IDs** while Sentinel transparently materializes the real values only at the final millisecond of execution.

---

## 🏛️ The Sentinel Vision: The Oracle Layer
SentinelClaw v0.0.1 is an **Autonomous Environment Guardian**. It moves beyond being a simple firewall and becomes the **Sentinel Intercept Layer** that manages the intelligence, secrets, and actions of every autonomous agent (e.g., OpenClaw, AutoGPT, Claude, Hermes) on the system.

### The Three Pillars of Guardianship:
1.  **Intelligence Sentinelty (The Middleman)**: Sentinel v0.0.1 acts as the **Unified Sentinel Proxy (USP)**. All agents point their LLM base URLs to Sentinel. Sentinel audits every Thought (Prompt) and Action (Tool Call) *before* it leaves the machine.
2.  **Autonomous Intent Reconciliation (The Harness)**: Sentinel v0.0.1 doesn't just block commands; it evaluates **Intent**. If an agent says it's "Optimizing the DB" but tries to `rm -rf /`, the **Deterministic Secret Shield** and the **LanguageHarness** synchronously veto the command.
3.  **Environment Protection (The Secure Body)**: Sentinel governs the physical reality of the host. Every tool-call is shadowed. A dual-process watchdog ensures that if an agent tries to "kill" the guardian, the watchdog enters **Hard Lockdown Mode**, freezing the environment and protecting the host.

---

## ⚡ Core Pillars of Sentinel
*   **🔒 Ghost ID Architecture**: Permanent "Air-Gapped" encryption. Agents never see, read, or leak your real API keys.
*   **⚖️ Intent-Aware Governance**: Per-agent autonomy modes (`strict`, `balanced`, `autonomous`) managed via Telegram.
*   **♻️ SafeTry Rollbacks**: Automatic filesystem snapshotting before high-risk agent actions. One command to undo a hallucination.
*   **🦾 Kernel-Level Self-Defense**: Seccomp-BPF + Landlock protection. Sentinel intercepts `SYS_KILL` to prevent agents from bypassing their supervisor.
*   **🧬 Dynamic Identity Extraction**: Zero-config agent tracking. Sentinel automatically identifies agents by project structure and execution path.
*   **📊 Vision Dashboard**: Real-time SSE telemetry stream of every materialization, redaction, and veto (Port 3333).

---

## 🏗️ Hybrid Architecture: Docker Mesh + Bare-Metal Agents
SentinelClaw uses a unique **High-Performance Hybrid Model**:
- **Sentinel Gateway (🐳 Docker)**: The security engine, vault, and identity mesh run inside an isolated Docker container for maximum hardening.
- **Autonomous Agents (💻 Host)**: Your agents (Claude, Hermes, etc.) run directly on your host or VPS for maximum performance and direct filesystem access.
- **The Connection**: Agents are "caged" by Sentinel Shims and Kernel Traps that transparently route all LLM traffic and sensitive syscalls into the Dockerized Gateway.

---

## ⚙️ Detailed Setup Guide

### 📋 Prerequisites
- **Docker & Docker-Compose**: Sentinel v0.0.1 is designed to run as a containerized security appliance.
- **Linux Host**: (Ubuntu/Debian recommended) for full Kernel-level hardening features (Seccomp-BPF/Landlock).
- **x86_64 Architecture**: The bare-metal `sentinel run` command (Seccomp-BPF syscall trapping, ptrace supervision) currently requires an x86_64 host. The proxy, vault, and dashboard components are architecture-agnostic.

### 🚀 Quickstart Deployment
Sentinel is a zero-dependency security appliance. Authorize your mission in seconds:
```bash
./setup.sh
```
*This bootstraps the Docker-mesh, initializes the Identity Mesh (SQLite), generates the security shims, and brings the gateway online.*

### ⚙️ Configuration
The primary configuration file is `sentinel.toml`. A reference template (`sentinel.toml.example`) is provided — `setup.sh` copies it automatically on first run. Key sections:

```toml
[general]
mode = "hybrid"           # "local_only", "hybrid", or "cloud_only"
socket_path = "/tmp/sentinel.sock"

[agents]
openclaw = 8080            # Per-agent port isolation (8080-8089)
hermes = 8081

[providers]
openai = "https://api.openai.com/v1"
openrouter = "https://openrouter.ai/api/v1"
```

---

## 📂 The "Secret-Blind" Agent Workflow
When an agent reads your environment through Sentinel, it sees a safe, governed view:

```bash
# Agent view of .env (Redacted)
OPENAI_API_KEY=sentinel_secret_openai_42
AWS_SECRET_KEY=sentinel_secret_aws_12
DB_PASS=sentinel_secret_password_9

# [🛡️ SentinelClaw] Real secrets are hidden. 
# Use these Ghost IDs; Sentinel will materialize them during execution.
```

### 🏎️ Bare-Metal Run
Execute any script with full hardware-level network isolation:
```bash
# Traps all network calls; forces routing through the local Secure Proxy
sentinel run python3 agent.py
```

---

## 📱 Sentinel Mission Control (Full Telegram Command List)
Sentinel is designed for **Remote Governance**. You manage your entire agentic stack via Telegram.

### 📡 Auditing & Real-Time Monitoring
- **/status** — Retrieves system health, connection status, and active agent ports.
- **/history** — Displays the last 10 security events, including redactions and materializations.
- **/logs** — Provides a secure link to the real-time Glassmorphic Dashboard (Port 3333).
- **/id** — Displays your Telegram Chat ID for security configuration.

### ⚖️ Identity Mesh & Vaulting
- **/add_key** — Vault a new API Key into the persistent mesh without touching a config file.
- **/add_pii** — Vault sensitive PII (SSN, names, addresses) to generate stable Ghost ID tokens.
- **/clear_mesh** — **Emergency:** Purges all local Ghost ID mappings from the encrypted SQLite database.
- **/allowlist** — Lists all currently trusted command patterns and safe system paths.

### ⚖️ Governance & Autonomy Control
- **/mode [target] [mode]** — Sets the autonomy level for a specific **PID** or **Agent Name**.
  - *Modes:* `strict` (Veto all), `balanced` (Audit all), `autonomous` (Logged but permitted).
- **/autonomy** — Configures the Global Autonomy levels for all unclassified agent processes.
- **/pii_on / pii_off** — Live-toggle the heuristic PII redaction layer.

### ♻️ SafeTry & Workspace Recovery
- **/snapshot_on / snapshot_off** — Toggles automatic filesystem checkpointing before SafeTry commands.
- **/rollback [pid]** — Instantly restores the workspace of the specified process to its pre-execution state.

### 💀 Emergency System Operations
- **/reboot / /restart** — Performs a graceful restart of the Sentinel Appliance process.
- **/stop** — **Emergency Shutdown:** Terminates the gateway and collapses the security proxy mesh.

---

**SentinelClaw: Identity. Governance. Invulnerability.**

*Authored by Morravex*

---

## License

This project is licensed under the [Apache License 2.0](LICENSE).

```
Copyright 2026 Morravex

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
