# Writing SentinelClaw-Friendly Example Keys

SentinelClaw's SecretShield automatically scrubs API keys, passwords, and tokens from agent-visible content. But sometimes you need to show example keys in documentation, README files, config templates, and code comments.

SentinelClaw has **documentation-aware scrubbing** that automatically skips certain content so your examples stay intact.

---

## What Gets Skipped Automatically

### 1. Comment Lines

Any line starting with a comment marker is never scrubbed:

```
# Python comment — OPENAI_API_KEY=sk-fake-example-key-12345
// JavaScript comment — gsk_fake_example_key_67890
/* C-style comment — sk-ant-fake-example-key */
* Javadoc comment — AKIAFAKEEXAMPLEKEY
-- SQL comment — stripe key: sk_test_fake123
<!-- HTML comment — fake token -->
```

### 2. The `sentinel:example` Marker

Protects **the marker line AND the next non-blank line**. Use this for single example values in config files.

```toml
# sentinel:example
OPENAI_API_KEY=sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz
```

```yaml
# sentinel:example
database_password: super_secret_example_password_123
```

```bash
# sentinel:example
export AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

### 3. The `sentinel:ignore` Block

Protects **everything between start and end markers**. Use this for multi-line examples, documentation sections, or config file templates.

```
# sentinel:ignore:start

# === Example Configuration ===
# These are example keys for documentation purposes only.

OPENAI_API_KEY=sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
DATABASE_URL=postgresql://user:password@localhost:5432/mydb
STRIPE_SECRET_KEY=sk_test_EXAMPLE_KEY_NOT_REAL_12345678

# sentinel:ignore:end
```

### 4. Inline `sentinel:ignore`

Protects just **a single line**. Useful for inline examples.

```
OPENAI_API_KEY=sk-proj-example-key-123  # sentinel:ignore
```

---

## Quick Reference

| Method | Scope | Use Case |
|---|---|---|
| Comment line (`#`, `//`, `/*`) | Single line | Inline comments with example keys |
| `sentinel:example` | Marker + next line | Single config value example |
| `sentinel:ignore:start/end` | Block | Multi-line examples, doc sections |
| `sentinel:ignore` (inline) | Single line | One-off inline example |

---

## Example: README Documentation

```markdown
## Configuration

Copy `.env.example` to `.env` and fill in your values:

# sentinel:ignore:start

OPENAI_API_KEY=sk-proj-your-key-here
AWS_SECRET_KEY=your-aws-secret-here
DATABASE_PASSWORD=your-db-password-here

# sentinel:ignore:end

Sentinel will redact these values automatically when agents read the file.
```

---

## Example: Config Template

```toml
[providers]
# sentinel:example
openai = "https://api.openai.com/v1"

# sentinel:example
groq = "https://api.groq.com/openai/v1"
```

---

## Example: Code Comments

```rust
// The vault stores encrypted keys.
// Example Ghost ID format: sentinel_openai_1
// Real key: sk-proj-abc123... (never shown to agents)

/* 
 * sentinel:ignore:start
 * Example keys for testing:
 * OPENAI_KEY=sk-test-abc123
 * AWS_KEY=AKIAEXAMPLE
 * sentinel:ignore:end
 */
```

---

## What Does NOT Get Skipped

The following will be scrubbed by Sentinel:

```bash
# These are NOT in comments, NOT in ignore blocks, NOT after sentinel:example
OPENAI_API_KEY=sk-proj-real-key-here        # ← SCRUBBED
DATABASE_PASSWORD=real-password              # ← SCRUBBED
```

**Rule of thumb:** If the key is in a plain assignment (not in a comment or ignore block), Sentinel will scrub it.

---

## For Documentation Authors

When writing documentation for SentinelClaw or projects that use it:

1. **Use comment markers** for inline examples — easiest approach
2. **Use `sentinel:example`** for config file examples — clean and explicit
3. **Use `sentinel:ignore:start/end`** for multi-line documentation blocks
4. **Always use obviously fake keys** — `sk-proj-abc123...`, `AKIAFAKEEXAMPLE`, `test_` prefixes
5. **Never use real keys** in documentation — even with ignore markers, real keys in public repos are a risk

---

## Testing Your Skip Rules

Run Sentinel's shell audit to verify your example keys won't be scrubbed:

```bash
sentinel run cat your-doc-file.md
```

If your example keys appear intact in the output, the skip rules are working.
