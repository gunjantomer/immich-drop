# Security Audit Report: Immich Drop Repository

**Date**: March 1, 2026  
**Auditor**: Qwen AI Assistant

---

## Executive Summary

A comprehensive security audit was performed on the Immich Drop repository. Several security vulnerabilities and concerns were identified, ranging from known CVEs in dependencies to configuration issues that could expose the application to various attack vectors.

**Overall Risk Assessment**: MODERATE-HIGH

---

## Critical Vulnerabilities

### 1. CVE-2024-24762 - ReDoS in python-multipart (HIGH)

| Field | Value |
|-------|-------|
| **CVE ID** | CVE-2024-24762 |
| **CVSS Score** | 7.5 (High) |
| **Vulnerability Type** | Regular Expression Denial of Service (ReDoS) |
| **Affected Package** | python-multipart |
| **Current Version** | 0.0.20 |
| **Fixed In** | 0.0.23+ |
| **Risk** | HIGH |

**Description**

The `python-multipart==0.0.20` version is vulnerable to Regular Expression Denial of Service (ReDoS). An attacker can send a specially crafted Content-Type header that causes the regular expression parser to consume excessive CPU resources, potentially stalling the application indefinitely.

**Affected File(s)**
- `requirements.txt` (line 14)

**Technical Details**

When using form data with multipart uploads, python-multipart uses a Regular Expression to parse the HTTP `Content-Type` header. An attacker could send a maliciously-crafted Content-Type option that is very difficult for the RegEx to process, consuming CPU resources and stalling indefinitely (minutes or more) while holding the main event loop.

**Remediation Steps**

1. Update `requirements.txt`:
   ```
   python-multipart==0.0.25
   ```

2. Reinstall dependencies:
   ```bash
   pip install -r requirements.txt --force-reinstall
   ```

3. Verify the version:
   ```bash
   pip show python-multipart
   ```

---

### 2. CVE-2024-47874 - Starlette Resource Allocation Vulnerability

| Field | Value |
|-------|-------|
| **CVE ID** | CVE-2024-47874 |
| **CVSS Score** | 8.7 (High) |
| **Affected Package** | starlette |
| **Current Version** | 0.47.3 |
| **Fixed In** | 0.40.0+ |
| **Risk** | MEDIUM-HIGH |

**Description**

Starlette versions before 0.40.0 are vulnerable to allocation of resources without limits or throttling. This vulnerability allows attackers to upload arbitrary large form fields, causing significant server slowdown due to excessive memory allocations and copying.

**Analysis**

Your current version `starlette==0.47.3` is patched against this vulnerability (released after 0.40.0). However, it's recommended to verify this explicitly and consider upgrading to the latest stable version for additional security improvements.

---

## Security Configuration Issues

### 3. CORS Overly Permissive Configuration (HIGH)

| Field | Value |
|-------|-------|
| **Location** | `app/app.py` lines 51-57 |
| **Severity** | HIGH |
| **CWE** | CWE-942 |

**Current Code**

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

**Risk Assessment**

This configuration violates CORS security best practices:
1. **Wildcard origins with credentials**: Using `allow_origins=["*"]` together with `allow_credentials=True` is a severe misconfiguration that allows any website to make authenticated requests to your API.
2. **Full method access**: `allow_methods=["*"]` exposes all HTTP methods including potentially dangerous ones like DELETE, PATCH, etc.
3. **Header wildcard**: `allow_headers=["*"]` allows any custom headers.

**Attack Vector**

An attacker could:
1. Create a malicious website
2. Use JavaScript to make authenticated POST requests to your Immich Drop API
3. Upload files or access protected endpoints on behalf of the user

**Remediation**

Update the CORS configuration to restrict origins:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("ALLOWED_ORIGINS", "http://localhost:8080")],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH"],
    allow_headers=["Content-Type", "Authorization", "Accept", "X-Requested-With"],
)
```

---

### 4. Session Secret Fallback (MEDIUM)

| Field | Value |
|-------|-------|
| **Location** | `app/config.py` line 53 |
| **Severity** | MEDIUM |

**Current Code**

```python
session_secret = os.getenv("SESSION_SECRET") or secrets.token_hex(32)
```

**Risk**

1. **Session invalidation on restart**: A new secret is generated on each startup, causing all existing sessions to be invalidated.
2. **Potential session hijacking window**: If an application crashes and restarts without a configured `SESSION_SECRET`, there's a window where sessions may not be properly secured.
3. **No explicit configuration requirement**: The app starts even when the secret is not explicitly set.

**Recommendation**

Require `SESSION_SECRET` to be explicitly set:

```python
session_secret = os.getenv("SESSION_SECRET")
if not session_secret:
    raise ValueError("SESSION_SECRET environment variable must be set for security")
```

---

### 5. Missing Security Headers (MEDIUM)

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |

**Current Status**

The application does not include essential HTTP security headers.

**Recommended Headers to Add**

| Header | Recommended Value | Purpose |
|--------|-------------------|---------|
| `X-Content-Type-Options` | `nosniff` | Prevent MIME-type sniffing |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` | Prevent clickjacking |
| `X-XSS-Protection` | `1; mode=block` | Enable XSS filter |
| `Content-Security-Policy` | See below | Protect against XSS/Injection |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Enforce HTTPS |

**CSP Recommendation**

For a simple upload application:

```
default-src 'self';
script-src 'self' 'unsafe-inline' cdn.tailwindcss.com;
style-src 'self' 'unsafe-inline' cdn.tailwindcss.com;
img-src 'self' data: https:;
font-src 'self' data:;
connect-src 'self' ws: wss:;
frame-ancestors 'none';
base-uri 'self';
form-action 'self';
```

---

### 6. Session Cookie Security (LOW-MEDIUM)

| Field | Value |
|-------|-------|
| **Location** | `app/app.py` line 50 |
| **Severity** | MEDIUM |

**Current Code**

```python
app.add_middleware(SessionMiddleware, secret_key=SETTINGS.session_secret, same_site="lax")
```

**Missing Security Attributes**
- No `secure=True` (should enforce HTTPS)
- No `httponly=True` (allows JavaScript access to session cookies)

**Recommendation**

Update the middleware configuration:

```python
app.add_middleware(
    SessionMiddleware,
    secret_key=SETTINGS.session_secret,
    same_site="lax",
    secure=SETTINGS.ssl_enabled if hasattr(SETTINGS, 'ssl_enabled') else False,
    httponly=True
)
```

---

### 7. Dockerfile - Running as Root (MEDIUM)

| Field | Value |
|-------|-------|
| **Location** | `Dockerfile` |
| **Severity** | MEDIUM |

**Current Status**

The container runs as the root user, which increases the attack surface if the application is compromised.

**Recommendation**

Add a non-root user to the Dockerfile:

```dockerfile
# Create a non-root user
RUN groupadd -r immich_drop && useradd -r -g immich_drop immich_drop

# Change ownership of app directory
RUN chown -R immich_drop:immich_drop /immich_drop /data

USER immich_drop

CMD ["python", "main.py"]
```

---

### 8. File Upload Validation (LOW-MEDIUM)

| Field | Value |
|-------|-------|
| **Location** | `app/app.py` api_upload function |
| **Severity** | LOW-MEDIUM |

**Current Implementation**

File upload validation relies primarily on:
- Frontend MIME type check: `^(image|video)\//`
- Extension whitelist

**Risk**

1. Client-side checks can be bypassed
2. No server-side file size limit enforcement
3. No content-type verification beyond extension

**Recommendation**

Add server-side validation:

```python
# Add maximum file size limit
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB

if len(raw) > MAX_FILE_SIZE:
    await send_progress(session_id, item_id, "error", 100, "File too large")
    return JSONResponse({"error": "file_too_large"}, status_code=413)
```

---

## Dependency Vulnerability Summary

| Package | Current Version | CVE Status | Action Required |
|---------|-----------------|------------|-----------------|
| fastapi | 0.116.1 | No critical CVEs | None |
| starlette | 0.47.3 | Patched against known issues | Verify version >= 0.40.0 |
| python-multipart | 0.0.20 | **CVE-2024-24762** | Upgrade to 0.0.25+ |
| requests | 2.32.5 | No critical CVEs | None |
| pillow | 11.3.0 | No critical CVEs | None |

---

## OWASP Top 10 Mapping

### A01:2021 - Broken Access Control
- **Status**: MODERATE RISK
- CORS configuration is overly permissive
- Session management needs improvement

### A02:2021 - Cryptographic Failures
- **Status**: MINIMAL RISK
- Password hashing uses PBKDF2 with 200,000 iterations (acceptable)
- Consider using SHA-512 for stronger hashing

### A03:2021 - Injection
- **Status**: LOW RISK
- SQL queries use parameterized statements correctly
- File content validation could be improved

### A05:2021 - Security Misconfiguration
- **Status**: HIGH RISK
- Missing security headers
- CORS misconfiguration
- No rate limiting

### A07:2021 - Identification and Authentication Failures
- **Status**: MEDIUM RISK
- Session management could be more secure
- Password requirements should be enforced server-side

---

## Compliance Considerations

### PCI-DSS
- Session cookies should enforce `secure` attribute
- Consider implementing rate limiting on login attempts

### NIST Cybersecurity Framework
- Access Control: Partially implemented (CORS needs improvement)
- Detection and Monitoring: Logging is present but could be enhanced
- Response: No incident response procedures documented

---

## Recommended Immediate Actions

### Priority 1 (Do Immediately)

1. **Upgrade python-multipart**
   ```bash
   pip install python-multipart>=0.0.25
   ```

2. **Configure CORS properly**
   ```python
   # In app/app.py, replace the CORSMiddleware configuration
   allow_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:8080").split(",")
   ```

3. **Set SESSION_SECRET environment variable**
   ```bash
   export SESSION_SECRET=$(openssl rand -hex 32)
   ```

### Priority 2 (This Week)

4. **Add security headers middleware**

5. **Implement file upload size limits**

6. **Enable secure cookie attributes**

### Priority 3 (Next Month)

7. **Run application as non-root user in Docker**

8. **Add rate limiting to API endpoints**

9. **Implement comprehensive logging and monitoring**

---

## Appendix: Security Headers Implementation Example

```python
from fastapi import FastAPI, Request
from fastapi.responses import Response

class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app
    
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        request = Request(scope)
        response = await self.app(scope, receive, send)
        
        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        # Optional: Add CSP
        if scope["path"] == "/":
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' cdn.tailwindcss.com; "
                "style-src 'self' 'unsafe-inline' cdn.tailwindcss.com; "
                "img-src 'self' data: https:; "
                "font-src 'self' data:; "
                "frame-ancestors 'none'; "
                "base-uri 'self'"
            )
        
        await send(response)
```

---

## Conclusion

The Immich Drop application has a solid foundation with proper use of parameterized SQL queries and secure password hashing. However, there are several critical security improvements needed:

1. **High Priority**: Fix CVE-2024-24762 in python-multipart
2. **High Priority**: Restrict CORS origins
3. **Medium Priority**: Add security headers
4. **Medium Priority**: Improve session cookie security

Implementing these recommendations will significantly improve the application's security posture and protect against known attack vectors.

---
*End of Security Audit Report*