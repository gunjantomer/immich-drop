# Security Audit – immich-drop

> Audit date: 2026-03-01. Scope: A:\cloud-data\code\immich-drop

---

## Part 1 – Dependency CVEs

### 🔴 HIGH – `starlette 0.47.3`

| CVE | Severity | Description | Fix |
|-----|----------|-------------|-----|
| **CVE-2025-62727** | **High** | **ReDoS in `FileResponse` / `StaticFiles`** – a crafted HTTP `Range` header triggers quadratic-time regex parsing, exhausting CPU (DoS). Affects 0.39.0 – 0.49.0. This app mounts `/static` via `StaticFiles` and uses `FileResponse` for HTML pages, making it directly exposed. | Upgrade to **starlette ≥ 0.49.1** (and update fastapi accordingly) |

> [!CAUTION]
> CVE-2025-62727 is directly exploitable by any unauthenticated visitor: just send `GET /static/... Range: bytes=0-1,0-1,...` to crash the server.

### 🟡 MEDIUM – `urllib3 2.5.0`

| CVE | Severity | Description | Fix |
|-----|----------|-------------|-----|
| **CVE-2025-66418** | Medium | Unbounded decompression chain – a malicious server can respond with unlimited nested compression layers, causing massive CPU/memory usage (DoS). Affects < 2.6.0. | Upgrade to **urllib3 ≥ 2.6.0** |
| **CVE-2025-66471** | Medium | Streaming API improperly handles highly compressed data, leading to CPU/memory exhaustion (DoS). Affects < 2.6.0. | Upgrade to **urllib3 ≥ 2.6.0** |

> [!NOTE]
> Both urllib3 CVEs require this service to fetch data from a malicious Immich server. Risk is low in a trusted-network setup, but matters if the Immich URL can be influenced externally.

### 🟡 MEDIUM – `uvicorn 0.35.0`

| CVE | Severity | Description | Fix |
|-----|----------|-------------|-----|
| **CVE-2025-55526** | Medium (pending analysis) | Path traversal vulnerability in uvicorn 0.35.0. Full analysis still pending from NVD. | Upgrade to **uvicorn ≥ 0.35.1** when available; monitor for clarification |

### 🟢 LOW – `python-multipart 0.0.20`

| CVE | Severity | Description | Fix |
|-----|----------|-------------|-----|
| **CVE-2026-24486** | Low | Path traversal when writing uploaded files if `UPLOAD_DIR` + `UPLOAD_KEEP_FILENAME=True` are set (non-default). This app does not use those options; **not directly exploitable here**. | Upgrade to **python-multipart ≥ 0.0.22** as hygiene |

### ✅ Clean (no known CVEs for pinned version)

| Package | Version |
|---------|---------|
| `fastapi` | 0.116.1 |
| `pillow` | 11.3.0 *(patches CVE-2025-48379)* |
| `requests` | 2.32.5 |
| `websockets` | 15.0.1 |
| `httpx` | 0.28.1 |
| `pydantic` / `pydantic_core` | 2.11.7 / 2.33.2 |
| `python-dotenv` | 1.1.1 |
| `itsdangerous` | 2.2.0 |
| `certifi` | 2025.8.3 |

> [!NOTE]
> The base image `python:3.11-slim` ships OS-level packages. Run `docker scout cves` or `trivy image python:3.11-slim` for OS-level CVEs (e.g., glibc, openssl). These are not covered here.

---

## Part 2 – Application-Level Security Issues

### 🔴 CRITICAL – Hardcoded API Key in `docker-compose.yml`

```yaml
# docker-compose.yml line 14
IMMICH_API_KEY: n7lO2oRFVhMXqI10YL8nfelIC9lZ8ND8AxZqx1XHiA
```

The real Immich API key is committed in plain text. Anyone with access to the repository (or the file) can directly call the Immich API with full permissions.

**Fix**: Rotate the key immediately. Use `docker secret` or a `.env` file (git-ignored) and reference it via `env_file: .env` in the compose file.

---

### 🔴 HIGH – Wildcard CORS

```python
# app.py line 42-47
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, ...)
```

`allow_origins=["*"]` combined with `allow_credentials=True` is an **invalid/insecure combination** — browsers refuse credentialed requests to a wildcard origin. This likely causes silent failures and leaves an unenforced CORS policy, allowing any site to make requests to this API.

**Fix**: Set `allow_origins` explicitly to your known origin(s) (e.g., `["https://your-domain.com"]`).

---

### 🔴 HIGH – `reload=True` Running in Production

```python
# main.py line 16
uvicorn.run("app.app:app", host=host, port=port, reload=True)
```

The `reload=True` flag starts a file-watcher worker. It is **only meant for development** and causes significant overhead and instability in production. It also loads Watchfiles (a native extension) unnecessarily.

**Fix**: Remove `reload=True` from production deployments. Use a `CMD` in `Dockerfile` that calls `uvicorn app.app:app --host 0.0.0.0 --port 8080` directly, or pass `UVICORN_RELOAD=false`.

---

### 🟡 MEDIUM – Path Traversal Risk in Chunk Upload Endpoints

```python
# app.py line 712-715
def _chunk_dir(session_id: str, item_id: str) -> str:
    safe_session = session_id.replace('/', '_')
    safe_item   = item_id.replace('/', '_')
    return os.path.join(CHUNK_ROOT, safe_session, safe_item)
```

Only `/` is replaced; **`..` (dot-dot)** and Windows-style `\` are not stripped. A crafted `session_id` like `..%2F..%2Fetc` (URL-decoded before arrival) or one containing `\` could potentially escape `/data/chunks`. Similarly the `name` (filename) from `meta.json` is used for `safe_name2` via `sanitize_filename`, which correctly blocks `/` and `\` – but only *after* the directory path is already constructed from unvalidated IDs.

**Fix**: Validate `session_id` and `item_id` against a strict allowlist (e.g., UUID-only regex) before using them in filesystem paths, or use `os.path.realpath()` + a prefix check.

---

### 🟡 MEDIUM – SHA-1 Used for De-duplication Checksum

```python
# app.py line 197-201
def sha1_hex(file_bytes: bytes) -> str:
    h = hashlib.sha1()
    h.update(file_bytes)
    return h.hexdigest()
```

SHA-1 is cryptographically broken and subject to collision attacks. A malicious actor could craft two different files with the same SHA-1 hash, causing the second to be silently skipped as a "duplicate." The checksum is also forwarded upstream to Immich via `x-immich-checksum`.

**Fix**: Use `hashlib.sha256()` or `hashlib.blake2b()`.

---

### 🟡 MEDIUM – IP Spoofing via `X-Forwarded-For` in Logging

```python
# app.py line 684
ip = (request.client.host if request and request.client else None) or request.headers.get('x-forwarded-for')
```

The `X-Forwarded-For` header is **user-controlled** and only trustworthy when the app is behind a reverse proxy that injects it. If the app is exposed directly, any client can spoof their IP in audit logs.

**Fix**: Trust `X-Forwarded-For` only if you know a trusted proxy is in front. Use Starlette's `TrustedHostMiddleware` or set `ProxyHeadersMiddleware` with a fixed trusted-proxy list.

---

### 🟡 MEDIUM – No Upload Size Limits / DoS via Large Files

There is no `Content-Length` or max-size guard on `POST /api/upload` or the chunk endpoints. A client can upload arbitrarily large payloads which are fully buffered in RAM:

```python
raw = await file.read()  # entire file into memory
```

**Fix**: Add a `MAX_UPLOAD_MB` environment variable and reject requests early via middleware or before reading, e.g., using `request.headers.get("content-length")`.

---

### 🟢 LOW – No Rate-Limiting on Auth or Upload Endpoints

`POST /api/login` and `POST /api/invite/{token}/auth` have no brute-force protection. An attacker can enumerate passwords with no throttling.

**Fix**: Add simple in-process rate limiting (e.g., `slowapi` for FastAPI) on auth endpoints.

---

### 🟢 LOW – Session Secret Falls Back to a Random Value Per Start

```python
# config.py line 54
session_secret = os.getenv("SESSION_SECRET") or secrets.token_hex(32)
```

If `SESSION_SECRET` is not set, the secret changes on every container restart, **invalidating all existing sessions**. This is a usability and mild security issue (forced re-logins after updates/restarts).

**Fix**: Always require `SESSION_SECRET` to be set via an environment variable. Log a warning or fail fast at startup if it is missing.

---

### 🟢 LOW – Invite Token Uses `uuid4().hex` (Not `secrets.token_urlsafe`)

```python
token = uuid.uuid4().hex  # 128-bit random, but from UUID RNG
```

UUIDs are generally considered random enough (122 bits of entropy), but `secrets.token_urlsafe(32)` is the Python-recommended approach for security tokens.

**Fix**: Replace `uuid.uuid4().hex` with `secrets.token_hex(32)`.

---

## Summary Table

| # | Finding | Severity | File |
|---|---------|----------|------|
| 1 | CVE-2025-62727 – Starlette ReDoS (StaticFiles/FileResponse) | 🔴 HIGH | `requirements.txt` |
| 2 | Hardcoded Immich API key | 🔴 CRITICAL | `docker-compose.yml` |
| 3 | Wildcard CORS + credentials | 🔴 HIGH | `app/app.py` |
| 4 | `reload=True` in production | 🔴 HIGH | `main.py` |
| 5 | CVE-2025-66418 / CVE-2025-66471 – urllib3 decompression DoS | 🟡 MEDIUM | `requirements.txt` |
| 6 | CVE-2025-55526 – uvicorn path traversal (pending) | 🟡 MEDIUM | `requirements.txt` |
| 7 | Path traversal in chunk upload dir construction | 🟡 MEDIUM | `app/app.py` |
| 8 | SHA-1 used for dedup checksum | 🟡 MEDIUM | `app/app.py` |
| 9 | IP spoofing via X-Forwarded-For in audit log | 🟡 MEDIUM | `app/app.py` |
| 10 | No file upload size limit (memory exhaustion DoS) | 🟡 MEDIUM | `app/app.py` |
| 11 | No rate-limiting on login / invite-auth | 🟢 LOW | `app/app.py` |
| 12 | CVE-2026-24486 – python-multipart path traversal (not triggered) | 🟢 LOW | `requirements.txt` |
| 13 | Session secret not required at startup | 🟢 LOW | `app/config.py` |
| 14 | Invite token from UUID instead of `secrets` | 🟢 LOW | `app/app.py` |

---

## Recommended `requirements.txt` Changes

```diff
-starlette==0.47.3
+starlette==0.49.1
-urllib3==2.5.0
+urllib3==2.6.0
-uvicorn==0.35.0
+uvicorn==0.35.1   # or latest stable
-python-multipart==0.0.20
+python-multipart==0.0.22
```

FastAPI must also be updated alongside Starlette (check compatibility).
