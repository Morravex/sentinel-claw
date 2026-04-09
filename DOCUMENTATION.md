# 🛰️ Technical Deep-Dive: The Sentinel Security Appliance

SentinelClaw v0.0.1 is an **Advanced Security Appliance** designed to provide **Transparent Secret Materialization** and **System-Wide Auditing** for autonomous agents and human operators.

---

## 1. 🏗️ The "Sentinel Identity" Mesh

### 🔴 Step A: In-Flight Redaction (The Ghost ID)
When an LLM or Agent mentions a sensitive value (API Key, PII):
1.  **Categorization**: The `SecretShield` identifies the secret provider (e.g., `openai`, `aws`, `stripe`) using 1,600+ regex signatures.
2.  **Ghost ID Mapping**: A typed ID is generated: `sentinel_secret_aws_1` or `sentinel_pii_email_2`.
3.  **Encrypted Persistence**: Every mapping is encrypted with **AES-256-GCM** and stored in the persistent `sentinel.db`.
4.  **Dynamic Ingestion**: Secrets can also be manually vaulted via the **Telegram `/add_key`** command or the **Web Dashboard Vault**, bypassing the need for static configuration files.

### 🟢 Step B: Intercept & Materialize (The Docker Bridge)
When a command containing a Ghost ID is executed:
1.  **Intercept**: The **Sentinel Docker-Shim** catches the host call (`python`, `node`, `bash`, etc.) and routes it into the Docker container via `docker exec`.
2.  **Materialization**: Sentinel decrypts the real value from the SQL mesh and **swaps** it back into the command in-memory for immediate execution.
3.  **Zero Footprint**: The real secret never exists on the host disk or LLM logs. It exists only in the RAM of the running process.

---

## 2. 🛡️ The Bare-Metal Airgap (Kernel-Level Isolation)

For environments where Docker is not used, Sentinel provides a high-performance **Bare-Metal Airgap** using Linux kernel primitives.

### ⚙️ Mechanism: Seccomp-BPF + Ptrace
When running an agent via `sentinel run <command>`, Sentinel acts as a user-space hypervisor:
1.  **Syscall Trapping**: Sentinel injects a **Seccomp-BPF** filter into the agent process tree. This filter specifically traps the `connect()` system call.
2.  **Ptrace Supervision**: The kernel pauses the agent on every connection attempt and notifies Sentinel.
3.  **Network Enforcement**: Sentinel inspects the destination IP/Port in the agent's memory. If the agent attempts to connect to any address other than `127.0.0.1:8080`, Sentinel overwrites the registers to return `-EPERM`, effectively severing the agent's direct internet access.
4.  **Shadow Scripting (JIT Materialization)**: If Sentinel detects a script file (e.g., `agent.py`) in the command arguments, it scans the file for Ghost IDs. It then creates an anonymous, RAM-only file descriptor (`memfd_create`), writes the materialized content into it, and transparently points the runtime (Python/Node) to the secure RAM buffer. This ensures real secrets **never touch the disk**, even if they are "hardcoded" in the agent's logic.
5.  **Transparent Routing**: Sentinel automatically injects environment variables (`OPENAI_BASE_URL`, etc.) to guide the agent framework to the local proxy.

### 🦾 Gateway Self-Defense (Invulnerability)
Sentinel protects itself from the very agents it supervises.
1.  **Kill-Switch Interception**: The Seccomp-BPF filter traps `SYS_KILL` attempts. If an agent tries to send a signal to the Sentinel Gateway PID (or any broad range that includes it), the syscall is blocked and returned as `-EPERM`.
2.  **Ptrace Preemption**: The supervisor detects if an agent attempts to call `ptrace()` on external processes to bypass tracing.

### 🔑 Dynamic TLS Interception (MitM)
To audit encrypted "Hands" (custom scripts making HTTPS calls), Sentinel:
1.  Generates a local, ephemeral **Root CA**.
2.  Injects the CA into the agent's session via `REQUESTS_CA_BUNDLE` and `SSL_CERT_FILE`.
3.  Performs JIT TLS termination to decrypt, audit/scrub, and re-encrypt traffic to upstream providers.

---

## 3. 🌐 Sentinel Dashboard (Port 3333)

Monitor your identity mesh in real-time with the **Sentinel Web Interface.**

### 📊 Features:
-   **SSE Event Stream**: Real-time visualization of proxy calls, secret redactions, materializations, and vetos.
-   **Identity Mesh Audit**: View all currently active Ghost IDs and their classification.
-   **Autonomy Monitor**: Visual tracking of active agent ports (8080-8089).
-   **Design Aesthetic**: Luxury **glassmorphism**, neon accents, and optimized dark-mode utility.

---

## 3. 🛰️ System-Wide Shimming (Host Integration)

Sentinel provides 40+ transparent host-to-container wrappers via the **[`setup.sh`](setup.sh)** script. This turns your entire Linux OS into a Sentinel-Protected environment.

### 🖥️ Supported Runtimes:
-   **Core**: `python`, `node`, `bun`, `deno`, `go`, `rustc`, `java`.
-   **Engines**: `docker`, `docker-compose`, `aws`, `gcloud`, `terraform`, `kubectl`, `git`, `make`.
-   **Runtimes**: `bash`, `sh`, `zsh`, `curl`, `wget`.

### 🚀 Usage:
```bash
# Add shims to your path
export PATH="$(pwd)/shims:$PATH"

# Now any host program can use Ghost IDs
aws s3 ls --profile sentinel_secret_aws_1
```

---

## 4. 🔏 Physical Security & Integrity

-   **At-Rest Encryption**: Using **PBKDF2** (100k rounds) to derive the master key from your unique `SENTINEL_PAIRING_KEY`.
-   **Agent Port Isolation**: Each agent's vault (`.env-hermes`, etc.) is strictly isolated. One agent cannot access the secrets of another unless explicit cross-mapping is configured.
-   **Remote Approval**: Every materialized command can be routed to your **Telegram Bridge** for final manual authorization.

### 🛡️ Sovereign PII Vaulting
Sentinel provides a dedicated **PII-Vault** for sensitive data (SSNs, Credit Cards, Health Records):
1.  **Deterministic Tokenization**: PII is replaced with non-reversible tokens that maintain format (e.g., `4111-XXXX-XXXX-1111`).
2.  **Access Control**: Only authorized processes with a valid `Sentinel-Token-Grant` can request the original PII, which is delivered via a secure, short-lived memory pipe.

### ♻️ SafeTry Workspace Snapshots
For high-risk operations, Sentinel provides an "Undo" layer:
1.  **Snapshot**: Before a **SafeTry** command is executed, Sentinel recursively copies the agent's CWD to `/tmp/sentinel_snap_{pid}`.
2.  **Rollback**: If the command results in unintended side effects, the operator can issue `/rollback <pid>` in Telegram to instantly restore the filesystem to its identical pre-execution state.

### 🧬 System-Agnostic Identity Extraction
Sentinel automatically identifies agents based on their execution path:
1.  **Leaf-First Search**: Sentinel scans the command path backwards from the filename (e.g., `dist/entry.js`).
2.  **Generic Filtering**: It ignores standard fillers (`node`, `bin`, `src`, `env`) to find the sovereign project folder.
3.  **Identity Suffixing**: It can strip architectural suffixes (e.g., `-gateway`, `-cli`) to identify the core agent (e.g., `openclaw`, `hermes`).
4.  **Automatic Provisioning**: Once identified, Sentinel injects the `SENTINEL_AGENT_NAME` tag into the environment for real-time telemetry.

**Sentinel Identity. Zero-Footprint. Infinite Security.**
