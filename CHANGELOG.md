# Changelog

All notable changes to the Sentinel project will be documented in this file.

## [0.0.1] - 2026-04-08

### Added
- **O(1) Mesh Caching**: Implemented dual-layer in-memory caches (`DashMap`) for Secret-to-GhostID and GhostID-to-Plaintext mappings. This eliminates redundant SHA256 hashing, AES decryption, and SQL queries for frequently accessed secrets.
- **SQLite WAL Mode**: Enabled Write-Ahead Logging for the sentinel database to allow high-concurrency event logging without blocking security audits.
- **Fail-Closed Shim Security**: Hardened `libsentry_scrub.so` to mask sensitive buffers with asterisks if the proxy vault service is unreachable, preventing accidental data leaks.
- **Persistent Governance**: Migrated Safelist, Autonomy Mode, and PII preferences to persistent SQLite storage, ensuring user configuration survives gateway restarts.
- **Per-Agent Autonomy Management**: Implemented granular trust levels keyed by Agent ID and PID, allowing individual security policies for different components.
- **Stealth Scrubbing Policy**: Shifted from aggressive process termination to transparent in-memory redaction for non-malicious sensitive file access, prioritizing agent availability.
- **CLI Autonomy Overrides**: Added `-strict`, `-balanced`, `-autonomous`, and `-permissive` flags to `sentinel run` for direct governance control.
- **Dynamic PII Toggle**: Added `/pii_on` and `/pii_off` Telegram commands to control the experimental PII shield live.
- **Obfuscation Normalization**: Added robust URL-decoding and Unicode unescaping to the `audit_context` pipeline to defeat evasive secret formatting.
- **Command-Line Audit Bypass Hardening**: Resolved a vulnerability where trailing spaces or null-byte artifacts could be used to bypass filename-based security filters.
- **Shim `mmap` Interception**: Expanded `libsentry_scrub.so` to intercept `mmap()` and `mremap()` calls for sensitive file mappings.
- **Documentation-Aware Scrubbing**: The scrubbing engine now automatically skips lines that fall inside comment regions, example markers, or sentinel:ignore blocks.
- **Landlock LSM Integration**: Added filesystem access control via Linux Landlock (kernel 6.8+) to restrict sensitive directory access.
- **Dynamic TLS MITM**: Automatic generation of a Local Root CA and injection into agent environments for transparent HTTPS auditing.
- **Entropy-Based Heuristic Scrubber**: Secondary scanning engine for detecting high-entropy obfuscated keys (Hex, ROT13, Base64).
- **SafeTry Workspace Snapshotting**: Implemented filesystem checkpointing for `/mode SafeTry` approvals. Sentinel copies the agent workspace to `/tmp` before execution, allowing full state restoration via `/rollback`.
- **Sovereign PII Vaulting**: Added dedicated PII category to the Identity Mesh. Users can now vault sensitive personal data (Names, Addresses, SSNs) via `/add_pii` to generate stable, redacted Ghost IDs.
- **Kernel-Level Self-Defense**: Hardened Seccomp-BPF filters to intercept `SYS_KILL` (62). Blocks agents from attempting to terminate the Sentinel Gateway process tree.
- **System-Agnostic Identity Extraction**: Implemented a robust, leaf-first path analysis engine that automatically identifies agents by project structure and execution path across arbitrary filesystem structures without hardcoded dependencies.

### Fixed
- **Materialization Oracle Leak**: Resolved a critical flaw where raw plaintext keys could be leaked in JSON proxy responses.
- **AES-GCM Nonce Reuse**: Switched to per-packet random nonces to prevent keystream recovery.
- **Shell Auditor Semantic Blindness**: Implemented Heavy Normalization to strip shell metacharacters before matching.
- **Async Reactor Blocking**: Offloaded heavy compute tasks to blocking threads to prevent proxy stalls.
- **Surgical Scrubbing**: Re-architected regex matches to use capture groups, preserving key names (`KEY=`) during redaction.
