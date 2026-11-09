# Memanto Security Audit

**Auditor:** ObscuraForager
**Date:** 2026-11-09
**Scope:** `memanto/` Python package (server, CLI, routes, services, middleware)
**Method:** Static code review of all `.py` files in the `memanto/` directory

---

## Executive Summary

Memanto is a well-structured FastAPI-based memory management service. The codebase shows strong security awareness — path traversal guards, constant-time comparison, CORS restrictions, and input validation are present in most critical paths. However, several issues were identified ranging from **High** to **Low** severity.

**Overall Risk Rating: MODERATE** — The most critical findings are configuration-dependent (default bind address, cookie security) and are partially mitigated by the middleware layer.

---

## Findings

### 1. [HIGH] Default Host Bind `0.0.0.0` with No TLS

**File:** `memanto/app/config.py` (Settings class)
**Line:** `HOST: str = "0.0.0.0"`

The server binds to all interfaces by default with no built-in TLS termination. The `docker-compose.yml` exposes port 8000 directly. While the `TrustedProxySchemeMiddleware` and `MEMANTO_REQUIRE_SECURE` flag provide opt-in protection, the **default configuration is insecure for any non-local deployment**.

**Impact:** Any network peer that can reach port 8000 can:
- Create agents and activate sessions (if loopback checks are bypassed via proxy)
- Read/write memories with a valid session token
- Intercept session cookies over plain HTTP

**Mitigation Present:**
- `MEMANTO_REQUIRE_SECURE=True` rejects plain HTTP (403)
- `MEMANTO_PROXY_ALLOWED_IPS` restricts trusted proxies
- Cookie `Secure` flag is set when the request arrives over HTTPS

**Recommendation:**
- Change default `HOST` to `127.0.0.1` and require explicit opt-in for `0.0.0.0`
- Document that `MEMANTO_REQUIRE_SECURE=True` is mandatory for non-local deployments
- Add a startup warning when `HOST=0.0.0.0` and `MEMANTO_REQUIRE_SECURE=False`

---

### 2. [HIGH] Session Cookie Over Plain HTTP from Non-Loopback

**File:** `memanto/app/routes/auth_deps.py`
**Function:** `set_session_cookie()`

The session cookie is issued with `secure=False` when the request arrives over plain HTTP. The code logs a warning but **still issues the cookie**. A network peer that can reach the port can intercept the `memanto_session_token` cookie and gain full memory read/write access.

**Impact:** Session hijacking on non-TLS deployments.

**Mitigation Present:**
- Warning is logged
- `SameSite=Strict` prevents CSRF
- `HttpOnly` prevents XSS-based theft
- Cookie-authenticated requests from non-loopback are rejected in `get_current_session()`

**Recommendation:**
- When `MEMANTO_REQUIRE_SECURE=True`, **refuse to issue** the cookie over plain HTTP (return 403) instead of just warning
- Consider making `Secure=True` mandatory when `HOST != 127.0.0.1`

---

### 3. [MEDIUM] Subprocess Calls in UI Router (On-Prem Restart)

**File:** `memanto/app/ui/routes/ui_router.py`
**Lines:** 507-560

The `_do_restart_onprem_backend()` function calls `subprocess.run()` with `moorcheh down` and `moorcheh up` commands. The arguments are constructed from `state.json` values (`embedding_provider`, `embedding_model`, `embedding_key`).

**Impact:** If `state.json` is writable by an unprivileged process (e.g., via a local file write vulnerability), an attacker could inject arguments to `moorcheh up`. The `embedding_key` is passed as a command-line argument, which may be visible in process listings (`/proc/*/cmdline` on Linux).

**Mitigation Present:**
- Arguments are passed as a list (not a shell string), preventing shell injection
- `check=True` and timeouts are set
- The endpoint requires on-prem backend to be active

**Recommendation:**
- Pass `embedding_key` via environment variable instead of command-line argument to avoid process listing exposure
- Validate `embedding_provider` and `embedding_model` against an allowlist before passing to subprocess

---

### 4. [MEDIUM] 5 GB File Upload Limit — Denial of Service Vector

**File:** `memanto/app/routes/memory.py`
**Function:** `upload_file()`

The maximum upload size is 5 GB per file. While the code streams in 1 MB chunks (good), a single 5 GB upload consumes 5 GB of disk space in `/tmp`. Multiple concurrent uploads could exhaust disk space.

**Impact:** Disk exhaustion leading to service unavailability.

**Mitigation Present:**
- Chunked streaming (1 MB chunks) prevents RAM exhaustion
- `tempfile.mkdtemp()` creates isolated temp directories
- `shutil.rmtree()` cleanup in `finally` block

**Recommendation:**
- Add a global concurrent upload limit (e.g., max 3 simultaneous uploads)
- Add a total disk usage check before accepting new uploads
- Consider reducing the limit to 500 MB for most use cases

---

### 5. [MEDIUM] YAML Loading from User-Writable Config

**File:** `memanto/app/config.py`
**Lines:** 30-40

The `~/.memanto/config.yaml` file is loaded with `yaml.safe_load()` (good — not `yaml.load()`). However, the file is in the user's home directory and is writable by any process running as the same user. A local process could modify this file to set environment variables like `ANSWER_MODEL`, `SUMMARY_MODEL`, `MEMANTO_BACKEND`, etc.

**Impact:** Local privilege escalation via config file modification (low risk in practice since it requires same-user access).

**Mitigation Present:**
- `yaml.safe_load()` prevents arbitrary code execution
- Values are used for configuration, not direct code execution

**Recommendation:**
- Set restrictive file permissions (0600) on `config.yaml` when writing
- Log a warning when config values change between restarts

---

### 6. [MEDIUM] API Key in Process Memory and Logs

**File:** `memanto/app/clients/moorcheh.py`, `memanto/app/routes/auth_deps.py`

The `MOORCHEH_API_KEY` is stored in the `Settings` object (in memory) and passed to the `MoorchehClient` constructor. The `redact_sensitive_text()` function is used in some error messages, but the API key could still appear in:
- Stack traces (if an exception includes the client object)
- Debug logs (if `DEBUG=True`)
- The `X-Api-Key` header in outbound requests (visible in network captures)

**Impact:** API key leakage through logs or error messages.

**Mitigation Present:**
- `redact_sensitive_text()` is applied to some error messages
- `secrets.compare_digest()` is used for credential comparison (constant-time)

**Recommendation:**
- Add a global logging filter that redacts the API key pattern from all log output
- Ensure `DEBUG=True` never logs request/response bodies that may contain the key
- Consider using a secrets manager for production deployments

---

### 7. [LOW] CORS Configuration — Regex-Based Origin Matching

**File:** `memanto/app/config.py`, `memanto/app/routes/auth_deps.py`

The `CORS_ORIGIN_REGEX` default is `^http://(localhost|127\.0\.0\.1)(:[0-9]+)?$`. The `_origin_is_allowed()` function uses `re.match()` (not `re.fullmatch()`) to test origins against this regex.

**Impact:** `re.match()` only anchors at the start, so an origin like `http://localhost:8000.evil.com` would **not** match (the regex requires the string to end after the optional port). However, if the regex were modified to be less strict, `re.match()` could allow prefix matches. The current default is safe.

**Mitigation Present:**
- The default regex is correctly anchored
- `ALLOWED_ORIGINS` list provides exact-match fallback

**Recommendation:**
- Use `re.fullmatch()` instead of `re.match()` for defense in depth
- Document that custom regexes must be fully anchored

---

### 8. [LOW] Session Token in Response Header

**File:** `memanto/app/routes/auth_deps.py`
**Function:** `get_current_session()`

When a session is auto-renewed, the new token is returned in the `X-Session-Token` response header. This header is visible to any JavaScript on the page (unlike the `HttpOnly` cookie).

**Impact:** If a XSS vulnerability exists, the renewed session token could be read from the response header by an attacker's script.

**Mitigation Present:**
- The cookie is `HttpOnly` (primary auth channel)
- The header is only set for API clients using `X-Session-Token`
- `SameSite=Strict` on the cookie

**Recommendation:**
- Consider returning the renewed token in the response body (JSON) instead of a header for API clients
- Or add a `Cache-Control: no-store` header to responses containing the token

---

### 9. [LOW] No Rate Limiting on Authentication Endpoints

**File:** `memanto/app/routes/auth_deps.py`, `memanto/app/routes/sessions.py`

There is no visible rate limiting on the session activation, login, or management endpoints. An attacker could brute-force the `MOORCHEH_API_KEY` or `MEMANTO_SECRET_KEY` by sending many requests to the management endpoints.

**Impact:** Brute-force attack on management credentials (mitigated by the key's entropy).

**Mitigation Present:**
- `secrets.compare_digest()` prevents timing attacks
- Keys are expected to be high-entropy

**Recommendation:**
- Add rate limiting (e.g., 10 requests/minute per IP) on authentication endpoints
- Consider adding account lockout after N failed attempts

---

### 10. [LOW] No Input Size Limit on Memory Content

**File:** `memanto/app/routes/memory.py`
**Function:** `remember()`

The `RememberRequest` model accepts a `content` field (string) with no explicit maximum length. While the `SOURCE_MAX_LENGTH` constant exists, it's used for source attribution, not the memory content itself. A very large memory content string could cause performance issues during embedding generation.

**Impact:** Performance degradation from very large memory entries.

**Mitigation Present:**
- Pydantic model validation
- The Moorcheh backend likely has its own limits

**Recommendation:**
- Add a `max_length` constraint to the `content` field in `RememberRequest`
- Return a clear 413 error for oversized content

---

## Positive Security Practices Observed

| Practice | Location |
|----------|----------|
| Path traversal prevention (CWE-22) | `memory.py` upload handler, `config.py` `get_conflict_report_path()` |
| Constant-time credential comparison | `auth_deps.py` `secrets.compare_digest()` |
| `HttpOnly` + `SameSite=Strict` cookies | `auth_deps.py` `set_session_cookie()` |
| `yaml.safe_load()` (not `yaml.load()`) | `config.py` |
| Chunked file upload streaming | `memory.py` `upload_file()` |
| Subprocess args as list (not shell string) | `ui_router.py` |
| Input validation with Pydantic models | All route handlers |
| CORS origin allowlist + regex | `config.py`, `auth_deps.py` |
| Loopback detection with IPv6-mapped IPv4 handling | `config.py` `is_loopback_host()` |
| Cross-site browser request detection | `auth_deps.py` `_is_cross_site_browser_request()` |
| `X-Forwarded-For` / `X-Real-IP` / `Forwarded` header parsing | `auth_deps.py` `_has_forwarded_non_loopback()` |
| Sensitive text redaction in error messages | `errors.py` `redact_sensitive_text()` |
| File extension allowlist on uploads | `memory.py` `upload_file()` |
| Temp file cleanup in `finally` block | `memory.py` `upload_file()` |
| Realpath verification for temp files | `memory.py` `upload_file()` |

---

## Summary Table

| # | Severity | Finding | File |
|---|----------|---------|------|
| 1 | HIGH | Default `0.0.0.0` bind with no TLS | `config.py` |
| 2 | HIGH | Session cookie over plain HTTP (warn but issue) | `auth_deps.py` |
| 3 | MEDIUM | Subprocess args from user-writable config | `ui_router.py` |
| 4 | MEDIUM | 5 GB upload limit — DoS vector | `memory.py` |
| 5 | MEDIUM | YAML config from user-writable file | `config.py` |
| 6 | MEDIUM | API key exposure in logs/errors | `moorcheh.py` |
| 7 | LOW | `re.match()` vs `re.fullmatch()` for CORS | `auth_deps.py` |
| 8 | LOW | Session token in response header | `auth_deps.py` |
| 9 | LOW | No rate limiting on auth endpoints | `sessions.py` |
| 10 | LOW | No max length on memory content | `memory.py` |

---

*Audit performed via static code review. No dynamic testing (fuzzing, penetration testing) was conducted.*
