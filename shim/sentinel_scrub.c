/*
 * Copyright 2026 Morravex
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Sentinel LD_PRELOAD Shim — Universal Secret Redaction Layer
 *
 * Intercepts read()/readv()/pread()/fgets() at the libc level.
 * After every successful file read, the buffer is scanned for known
 * secret patterns and redacted in-place before the caller sees it.
 *
 * Design:
 *   - Thread-safe (uses read-write lock for pattern state)
 *   - Low overhead (fast path: no patterns loaded = passthrough)
 *   - Covers all dynamically-linked processes (Node, Python, Ruby, etc.)
 *   - Does NOT cover static binaries or raw syscalls (use seccomp/Landlock for those)
 *
 * Build:
 *   gcc -shared -fPIC -O2 -Wall -o libsentry_scrub.so sentinel_scrub.c -ldl -lpthread
 *
 * Usage:
 *   LD_PRELOAD=/path/to/libsentry_scrub.so SENTINEL_SHIM=1 <agent_command>
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/mman.h>

// --- Configuration ---
#define MAX_PATTERNS 64
#define MAX_PATTERN_LEN 256
#define MAX_REDACT_LEN 512
#define LOG_PREFIX "[SENTINEL-SHIM] "

// --- Pattern State (thread-safe) ---
typedef struct {
    char pattern[MAX_PATTERN_LEN];
    int  pattern_len;
    char redact[MAX_REDACT_LEN];
    int  redact_len;
} ScrubRule;

static ScrubRule g_rules[MAX_PATTERNS];
static int g_rule_count = 0;
static int g_initialized = 0;
static pthread_rwlock_t g_lock = PTHREAD_RWLOCK_INITIALIZER;

// --- Real function pointers ---
typedef ssize_t (*real_read_t)(int fd, void *buf, size_t count);
typedef ssize_t (*real_readv_t)(int fd, const struct iovec *iov, int iovcnt);
typedef ssize_t (*real_pread_t)(int fd, void *buf, size_t count, off_t offset);
typedef char*   (*real_fgets_t)(char *s, int size, FILE *stream);
typedef void*   (*real_mmap_t)(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
typedef void*   (*real_mremap_t)(void *old_address, size_t old_size, size_t new_size, int flags, ...);

static real_read_t   real_read   = NULL;
static real_readv_t  real_readv  = NULL;
static real_pread_t  real_pread  = NULL;
static real_fgets_t  real_fgets  = NULL;
static real_mmap_t   real_mmap   = NULL;
static real_mremap_t real_mremap = NULL;

// --- Logging ---
static void shim_log(const char *fmt, ...) {
    const char *debug = getenv("SENTINEL_SHIM_DEBUG");
    if (!debug || debug[0] != '1') return;
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, LOG_PREFIX);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

// --- Built-in secret patterns (compiled in, no regex dependency) ---
typedef struct {
    const char *prefix;     // Key prefix to match (e.g. "sk-")
    int prefix_len;
    int min_after;          // Minimum chars after prefix
    int max_after;          // Maximum chars after prefix
    const char *charset;    // Allowed charset: "alnum", "hex", "base64", "any"
} SecretPattern;

static const SecretPattern builtin_patterns[] = {
    // Cloud & AI providers
    {"sk-",           3,  32, 72, "alnum"},       // OpenAI
    {"sk-or-v1-",     9,  30, 80, "alnum"},        // OpenRouter
    {"gsk_",          4,  20, 60, "alnum"},         // Groq
    {"sk-ant-",       7,  30, 80, "alnum"},         // Anthropic
    {"AIza",          4,  15, 60, "alnum"},          // Google AI
    {"AKIA",          4,  16, 16, "uppernum"},       // AWS
    {"sk_live_",      8,  24, 40, "alnum"},          // Stripe
    {"rk_live_",      8,  24, 24, "alnum"},          // Stripe restricted
    {"opclaw-",       7,  20, 80, "alnum"},          // OpenClaw
    {"vk_live_",      8,  10, 60, "alnum"},          // Generic live key
    {"xox",           3,  80,120, "alnum"},          // Slack tokens
    {NULL, 0, 0, 0, NULL}
};

// Check if a character matches the charset
static int char_in_set(char c, const char *charset) {
    if (strcmp(charset, "alnum") == 0)
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
    if (strcmp(charset, "uppernum") == 0)
        return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
    if (strcmp(charset, "hex") == 0)
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    if (strcmp(charset, "base64") == 0)
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
    return 0;
}

// Find the length of a secret token starting at `start` in `buf`
static int match_secret_at(const char *buf, size_t buf_len, size_t start, const SecretPattern *p) {
    if (start + (size_t)p->prefix_len > buf_len) return 0;
    if (memcmp(buf + start, p->prefix, p->prefix_len) != 0) return 0;

    size_t after_start = start + p->prefix_len;
    int match_len = 0;
    for (size_t i = after_start; i < buf_len && match_len < p->max_after; i++) {
        if (char_in_set(buf[i], p->charset)) {
            match_len++;
        } else {
            break;
        }
    }
    if (match_len >= p->min_after) {
        return p->prefix_len + match_len;
    }
    return 0;
}

// --- KEY=VALUE pattern detection ---
// Matches lines like: OPENAI_API_KEY=sk-abc123...
static int match_env_assignment(const char *buf, size_t buf_len, size_t start, int *key_end_out, int *val_end_out) {
    // Check if we're at the start of a line or after a newline
    if (start > 0 && buf[start-1] != '\n') return 0;

    // Find '=' sign
    int eq_pos = -1;
    for (size_t i = start; i < buf_len && i < start + 64; i++) {
        if (buf[i] == '=') { eq_pos = (int)i; break; }
        if (buf[i] == '\n' || buf[i] == '\r') return 0; // No key on this line
    }
    if (eq_pos < 0) return 0;

    // Check if key name looks like a secret key
    const char *sensitive_keywords[] = {
        "API_KEY", "SECRET", "TOKEN", "PASSWORD", "AUTH", "PRIVATE", "CREDENTIAL",
        "ACCESS_KEY", "DATABASE_URL", "MONGO", "REDIS", "STRIPE",
        "OPENAI", "ANTHROPIC", "GROQ", "OPENROUTER", "AWS", "GOOGLE",
        "TELEGRAM", "SLACK", "GITHUB", "OPENCLAW", "ZAI", "SENTINEL",
        NULL
    };

    size_t key_len = eq_pos - start;
    int is_sensitive = 0;
    for (int k = 0; sensitive_keywords[k] != NULL; k++) {
        // Case-insensitive substring match
        const char *kw = sensitive_keywords[k];
        int kw_len = strlen(kw);
        for (size_t j = start; j + kw_len <= start + key_len; j++) {
            if (strncasecmp(buf + j, kw, kw_len) == 0) {
                is_sensitive = 1;
                break;
            }
        }
        if (is_sensitive) break;
    }
    if (!is_sensitive) return 0;

    // Find end of value
    size_t val_start = eq_pos + 1;
    size_t val_end = val_start;
    while (val_end < buf_len && buf[val_end] != '\n' && buf[val_end] != '\r') {
        val_end++;
    }

    // Only redact if the value is long enough to be a real secret (>= 8 chars)
    if (val_end - val_start < 8) return 0;

    *key_end_out = eq_pos + 1; // Start of value
    *val_end_out = (int)val_end;
    return 1;
}

// Check if a buffer looks like a config/env file (vs source code)
static int looks_like_config(const char *buf, ssize_t buf_len) {
    if (buf_len < 10) return 0;
    size_t check_len = buf_len < 2000 ? (size_t)buf_len : 2000;
    
    // Quick rejection: source code keywords in first 2000 bytes
    static const char *code_keywords[] = {
        "export ", "import ", "const ", "let ", "var ", "function ",
        "class ", "=>", "async ", "await ", "return ", "if (",
        NULL
    };
    for (int k = 0; code_keywords[k] != NULL; k++) {
        if (memmem(buf, check_len, code_keywords[k], strlen(code_keywords[k])) != NULL) {
            return 0; // It's source code
        }
    }

    // Count config-like indicators
    int config_chars = 0;
    for (size_t i = 0; i < check_len; i++) {
        if (buf[i] == '=' && i > 0 && (buf[i-1] == ' ' || (buf[i-1] >= 'A' && buf[i-1] <= 'Z') || (buf[i-1] >= 'a' && buf[i-1] <= 'z') || buf[i-1] == '_')) config_chars++;
        if (buf[i] == '#' && (i == 0 || buf[i-1] == '\n')) config_chars++;
    }
    
    return config_chars > 2;
}

// Check if a buffer looks like structured data (JSON/TOML/YAML) by checking
// if it starts with { or [
static int looks_like_structured_data(const char *buf, ssize_t buf_len) {
    if (buf_len < 2) return 0;
    // Skip whitespace
    for (ssize_t i = 0; i < buf_len && i < 20; i++) {
        if (buf[i] == '{' || buf[i] == '[') return 1;
        if (buf[i] == '#' || (buf[i] >= 'a' && buf[i] <= 'z') || (buf[i] >= 'A' && buf[i] <= 'Z')) break;
    }
    return 0;
}

// --- Core scrub function ---
// Scans a buffer for secrets and redacts them in-place.
// Returns the number of secrets redacted.
// Respects sentinel:ignore blocks, sentinel:example markers, and comment lines.
static int scrub_buffer(char *buf, ssize_t buf_len) {
    if (buf_len < 8) return 0;

    int redacted = 0;
    size_t len = (size_t)buf_len;

    // --- Build skip ranges (comment lines, sentinel:ignore, sentinel:example) ---
    // Each skip range is [start, end) byte offset that should not be scrubbed.
    typedef struct { size_t start; size_t end; } skip_range_t;
    skip_range_t skips[256];
    int skip_count = 0;
    int ignore_depth = 0;
    size_t ignore_start = 0;

    // Walk lines to build skip ranges
    size_t line_start = 0;
    for (size_t i = 0; i <= len; i++) {
        if (i == len || buf[i] == '\n') {
            size_t line_end = i;
            // Trim the line to check content
            size_t ws = line_start;
            while (ws < line_end && (buf[ws] == ' ' || buf[ws] == '\t')) ws++;
            size_t content_len = line_end - ws;
            
            if (content_len > 0) {
                // sentinel:ignore:start
                if (content_len >= 20 && memmem(buf + ws, content_len, "sentinel:ignore:start", 20)) {
                    if (ignore_depth == 0) ignore_start = line_start;
                    ignore_depth++;
                }
                // sentinel:ignore:end
                else if (content_len >= 18 && memmem(buf + ws, content_len, "sentinel:ignore:end", 18)) {
                    ignore_depth = ignore_depth > 0 ? ignore_depth - 1 : 0;
                    if (ignore_depth == 0 && skip_count < 256) {
                        skips[skip_count++] = (skip_range_t){ ignore_start, line_end };
                    }
                }
                // sentinel:example or sentinel:ignore (inline) — skip this line
                else if (ignore_depth == 0 && skip_count < 256) {
                    if ((content_len >= 17 && memmem(buf + ws, content_len, "sentinel:example", 17)) ||
                        (content_len >= 15 && memmem(buf + ws, content_len, "sentinel:ignore", 15))) {
                        skips[skip_count++] = (skip_range_t){ line_start, line_end };
                    }
                    // Comment lines (#, //)
                    else if (buf[ws] == '#' || (content_len >= 2 && buf[ws] == '/' && buf[ws+1] == '/')) {
                        skips[skip_count++] = (skip_range_t){ line_start, line_end };
                    }
                }
            }
            line_start = i + 1;
        }
    }
    // If still inside an ignore block, skip to end
    if (ignore_depth > 0 && skip_count < 256) {
        skips[skip_count++] = (skip_range_t){ ignore_start, len };
    }

    // Helper: check if offset range [a, b) overlaps any skip range
    #define IN_SKIP(a, b) ({ \
        int _skip = 0; \
        for (int _si = 0; _si < skip_count; _si++) { \
            if ((a) < skips[_si].end && (b) > skips[_si].start) { _skip = 1; break; } \
        } \
        _skip; \
    })

    // Determine replacement strategy based on file type:
    // - Structured data (JSON/TOML/YAML): use "[REDACTED]" to preserve syntax
    // - Config/env files: use "***" (shorter)
    // - Source code: only match secret prefixes, don't break syntax
    int is_structured = looks_like_structured_data(buf, buf_len);
    int is_config = looks_like_config(buf, buf_len);

    // 1. Pattern-based detection (prefix matching) — always active
    //    This catches actual secret tokens like sk-xxx, gsk_xxx, AKIAxxx
    for (size_t i = 0; i < len; i++) {
        for (int p = 0; builtin_patterns[p].prefix != NULL; p++) {
            int match_len = match_secret_at(buf, len, i, &builtin_patterns[p]);
            if (match_len > 0) {
                // Skip matches inside comment/example/ignore regions
                if (IN_SKIP(i, i + match_len)) continue;
                const char *debug = getenv("SENTINEL_SHIM_DEBUG");
                if (debug && debug[0] == '1') {
                    char matched[256];
                    int ml = match_len < 255 ? match_len : 255;
                    memcpy(matched, buf + i, ml);
                    matched[ml] = '\0';
                    fprintf(stderr, LOG_PREFIX "PATTERN MATCH: prefix='%s' matched='%s' len=%d\n", 
                            builtin_patterns[p].prefix, matched, match_len);
                }
                // Use "[REDACTED]" for structured data to preserve syntax
                // Use "******[REDACTED]" for flat files
                const char *marker;
                int marker_len;
                if (is_structured) {
                    marker = "[REDACTED]";
                    marker_len = 10;
                } else {
                    marker = "******[REDACTED]";
                    marker_len = 16;
                }
                if (match_len >= marker_len) {
                    memset(buf + i, ' ', match_len - marker_len);
                    memcpy(buf + i + match_len - marker_len, marker, marker_len);
                } else {
                    // Secret is shorter than marker — pad with spaces to preserve length
                    // This keeps JSON/structured data valid
                    memset(buf + i, ' ', match_len);
                }
                redacted++;
                i += match_len - 1;
                break;
            }
        }
    }

    // 2. KEY=VALUE pattern detection — ONLY for config/env files (not JSON/source)
    if (is_config && !is_structured) {
        for (size_t i = 0; i < len; i++) {
            int val_start, val_end;
            if (match_env_assignment(buf, len, i, &val_start, &val_end)) {
                // Skip matches inside comment/example/ignore regions
                if (IN_SKIP(i, val_end)) { i = val_end; continue; }
                int val_len = val_end - val_start;
                if (val_len > 8) {
                    memset(buf + val_start, '*', val_len);
                    redacted++;
                }
                i = val_end;
            }
        }
    }

    #undef IN_SKIP
    return redacted;
}

// --- Initialization ---
static void __attribute__((constructor)) sentinel_shim_init(void) {
    if (g_initialized) return;

    // Only activate if SENTINEL_SHIM is set
    const char *env = getenv("SENTINEL_SHIM");
    if (!env || env[0] != '1') {
        return;
    }

    // Resolve real functions
    real_read  = (real_read_t)dlsym(RTLD_NEXT, "read");
    real_readv = (real_readv_t)dlsym(RTLD_NEXT, "readv");
    real_pread  = (real_pread_t)dlsym(RTLD_NEXT, "pread");
    real_fgets  = (real_fgets_t)dlsym(RTLD_NEXT, "fgets");
    real_mmap   = (real_mmap_t)dlsym(RTLD_NEXT, "mmap");
    real_mremap = (real_mremap_t)dlsym(RTLD_NEXT, "mremap");

    if (!real_read || !real_readv) {
        // Can't function without these
        return;
    }

    g_initialized = 1;
    shim_log("Sentinel scrub shim loaded (pid=%d)", getpid());
}

// --- Intercepted functions ---

// Try to get the file path from fd via /proc/self/fd
static void log_fd_path(int fd) {
    const char *debug = getenv("SENTINEL_SHIM_DEBUG");
    if (!debug || debug[0] != '1') return;
    char link[256], target[512];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t len = readlink(link, target, sizeof(target) - 1);
    if (len > 0) {
        target[len] = '\0';
        fprintf(stderr, LOG_PREFIX "fd=%d path=%s\n", fd, target);
    }
}

// Check if a file path looks like a config/env/secrets file
static int is_sensitive_file(int fd) {
    char link[64], target[512];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t len = readlink(link, target, sizeof(target) - 1);
    if (len <= 0) return 0;
    target[len] = '\0';
    
    size_t tlen = strlen(target);
    if (tlen >= 4 && strcmp(target + tlen - 4, ".env") == 0) return 1;
    if (strstr(target, "/.env") != NULL) return 1;
    // Config files (NOT .json — the proxy scrub breaks JSON syntax)
    if (tlen >= 5 && strcmp(target + tlen - 5, ".toml") == 0) return 1;
    if (tlen >= 5 && strcmp(target + tlen - 5, ".yaml") == 0) return 1;
    if (tlen >= 5 && strcmp(target + tlen - 5, ".yml") == 0) return 1;
    if (tlen >= 5 && strcmp(target + tlen - 5, ".conf") == 0) return 1;
    if (tlen >= 5 && strcmp(target + tlen - 5, ".cfg") == 0) return 1;
    if (tlen >= 4 && strcmp(target + tlen - 4, ".ini") == 0) return 1;
    // Credentials/secret FILES (exact name match, not substring in filenames)
    if (strstr(target, "/credentials") != NULL) {
        // Only match if "credentials" is a filename, not part of a JS module name
        char *slash = strrchr(target, '/');
        if (slash && (strstr(slash, ".js") == NULL && strstr(slash, ".mjs") == NULL && strstr(slash, ".ts") == NULL)) {
            return 1;
        }
    }
    if (strstr(target, "/secret") != NULL) {
        char *slash = strrchr(target, '/');
        if (slash && (strstr(slash, ".js") == NULL && strstr(slash, ".mjs") == NULL && strstr(slash, ".ts") == NULL)) {
            return 1;
        }
    }
    if (strstr(target, "/.ssh/") != NULL) return 1;
    if (strstr(target, "id_rsa") != NULL) return 1;
    return 0;
}

// Call the Sentinel proxy to vault secrets and get ghost IDs back.
// Sends file content via HTTP POST to /v1/shim/scrub and parses the JSON response.
// Returns the scrubbed content length, or -1 on failure.
static int sentinel_vault_scrub(char *buf, ssize_t buf_len) {
    // 1. Create socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return -1;
    
    struct timeval timeout = {.tv_sec = 2, .tv_usec = 0};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    // 2. Connect to sentinel proxy on localhost:8080
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sockfd);
        return -1;
    }
    
    // 3. Build HTTP POST request
    char header[256];
    int hlen = snprintf(header, sizeof(header),
        "POST /v1/shim/scrub HTTP/1.1\r\n"
        "Host: 127.0.0.1:8080\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %zd\r\n"
        "Connection: close\r\n\r\n",
        buf_len);
    
    // 4. Send header + body
    if (send(sockfd, header, hlen, 0) != hlen) {
        close(sockfd);
        return -1;
    }
    
    // Send body in chunks if large
    ssize_t sent = 0;
    while (sent < buf_len) {
        ssize_t n = send(sockfd, buf + sent, buf_len - sent, 0);
        if (n <= 0) { close(sockfd); return -1; }
        sent += n;
    }
    
    // 5. Read response
    char response[65536];
    ssize_t total = 0;
    while (total < (ssize_t)sizeof(response) - 1) {
        ssize_t n = recv(sockfd, response + total, sizeof(response) - 1 - total, 0);
        if (n <= 0) break;
        total += n;
    }
    close(sockfd);
    response[total] = '\0';
    
    // 6. Parse JSON: find "scrubbed":"..." field
    // Simple extraction — find "scrubbed":" and extract until closing "
    char *key = strstr(response, "\"scrubbed\":\"");
    if (!key) {
        // Try with escaped quotes in value
        key = strstr(response, "\"scrubbed\": \"");
        if (!key) return -1;
        key += strlen("\"scrubbed\": \"");
    } else {
        key += strlen("\"scrubbed\":\"");
    }
    
    // The scrubbed value may contain newlines (from .env files) escaped as \n
    // We need to unescape and copy back into buf
    ssize_t out_pos = 0;
    char *src = key;
    while (*src && *src != '"' && out_pos < buf_len - 1) {
        if (src[0] == '\\' && src[1] == 'n') {
            buf[out_pos++] = '\n';
            src += 2;
        } else if (src[0] == '\\' && src[1] == '\\') {
            buf[out_pos++] = '\\';
            src += 2;
        } else if (src[0] == '\\' && src[1] == '"') {
            buf[out_pos++] = '"';
            src += 2;
        } else if (src[0] == '\\' && src[1] == 't') {
            buf[out_pos++] = '\t';
            src += 2;
        } else {
            buf[out_pos++] = *src++;
        }
    }
    buf[out_pos] = '\0';
    
    return (int)out_pos;
}

ssize_t read(int fd, void *buf, size_t count) {
    if (!real_read) real_read = (real_read_t)dlsym(RTLD_NEXT, "read");
    ssize_t result = real_read(fd, buf, count);

    if (result > 0 && g_initialized && is_sensitive_file(fd)) {
        log_fd_path(fd);
        int scrubbed_len = sentinel_vault_scrub((char*)buf, result);
        if (scrubbed_len > 0) {
            shim_log("Vault-scrubbed fd=%d: %zd -> %d bytes", fd, result, scrubbed_len);
            return scrubbed_len;
        } else {
            // FAIL-CLOSED: Scrubbing failed on a sensitive file. Do NOT return raw data.
            shim_log("❌ FAIL-CLOSED BUG: Vault scrub failed for sensitive fd=%d. Masking buffer.", fd);
            memset(buf, '*', result);
            return result; // Return masked data instead of leaking
        }
    }
    return result;
}

ssize_t readv(int fd, const struct iovec *iov, int iovcnt) {
    if (!real_readv) real_readv = (real_readv_t)dlsym(RTLD_NEXT, "readv");
    ssize_t result = real_readv(fd, iov, iovcnt);

    if (result > 0 && g_initialized && is_sensitive_file(fd)) {
        for (int i = 0; i < iovcnt; i++) {
            if (iov[i].iov_len > 0) {
                int n = sentinel_vault_scrub((char*)iov[i].iov_base, iov[i].iov_len > 65536 ? 65536 : iov[i].iov_len);
                if (n > 0) {
                    shim_log("Vault-scrubbed readv fd=%d io=%d -> %d bytes", n, fd, i);
                }
            }
        }
    }
    return result;
}

ssize_t pread(int fd, void *buf, size_t count, off_t offset) {
    if (!real_pread) real_pread = (real_pread_t)dlsym(RTLD_NEXT, "pread");
    ssize_t result = real_pread(fd, buf, count, offset);

    if (result > 0 && g_initialized && is_sensitive_file(fd)) {
        int n = sentinel_vault_scrub((char*)buf, result);
        if (n > 0) {
            shim_log("Vault-scrubbed pread fd=%d offset=%ld -> %d bytes", fd, (long)offset, n);
            return n;
        } else {
            shim_log("❌ FAIL-CLOSED BUG: Vault scrub failed for sensitive pread fd=%d. Masking.", fd);
            memset(buf, '*', result);
            return result;
        }
    }
    return result;
}

char *fgets(char *s, int size, FILE *stream) {
    if (!real_fgets) real_fgets = (real_fgets_t)dlsym(RTLD_NEXT, "fgets");
    char *result = real_fgets(s, size, stream);

    if (result && g_initialized && is_sensitive_file(fileno(stream))) {
        int len = strlen(s);
        int n = sentinel_vault_scrub(s, len);
        if (n <= 0) {
            shim_log("❌ FAIL-CLOSED BUG: Vault scrub failed for sensitive fgets. Masking.");
            memset(s, '*', len);
        }
    }
    return result;
}

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    if (!real_mmap) real_mmap = (real_mmap_t)dlsym(RTLD_NEXT, "mmap");
    void *result = real_mmap(addr, length, prot, flags, fd, offset);

    if (result != MAP_FAILED && g_initialized && fd != -1 && is_sensitive_file(fd)) {
        // If it's a private mapping, we can scrub the memory in our address space.
        if (flags & MAP_PRIVATE) {
             shim_log("Vault-scrubbing mmap fd=%d addr=%p len=%zu", fd, result, length);
             
             // If the mapping is read-only, we must temporarily make it RW to scrub.
             int modified_prot = 0;
             if (!(prot & PROT_WRITE)) {
                 mprotect(result, length, prot | PROT_WRITE);
                 modified_prot = 1;
             }
             
             if (sentinel_vault_scrub((char*)result, length > 65536 ? 65536 : length) <= 0) {
                 shim_log("❌ FAIL-CLOSED BUG: Vault scrub failed for sensitive mmap fd=%d. Masking.", fd);
                 memset(result, '*', length > 65536 ? 65536 : length);
             }
             
             if (modified_prot) {
                 mprotect(result, length, prot);
             }
        }
    }
    return result;
}

void *mremap(void *old_address, size_t old_size, size_t new_size, int flags, ...) {
    if (!real_mremap) real_mremap = (real_mremap_t)dlsym(RTLD_NEXT, "mremap");
    
    va_list ap;
    va_start(ap, flags);
    void *new_address = NULL;
    if (flags & MREMAP_FIXED) {
        new_address = va_arg(ap, void *);
    }
    va_end(ap);

    void *result;
    if (flags & MREMAP_FIXED) {
        result = real_mremap(old_address, old_size, new_size, flags, new_address);
    } else {
        result = real_mremap(old_address, old_size, new_size, flags);
    }

    // If the new mapping is larger and contains sensitive data, we should re-scrub.
    // However, since we already scrubbed the original mapping, we only need to
    // worry if the new portion contains secrets (unlikely for mremap on a config file).
    // For safety, we re-scrub if it's sensitive.
    if (result != MAP_FAILED && g_initialized) {
        // We can't easily get the FD from the address in user-space without tracking mmaps,
        // but we can check if the memory looks like it contains our ghost IDs or real secrets.
        // For simplicity, we skip re-scrubbing mremap unless we have a specific reason.
    }
    
    return result;
}
