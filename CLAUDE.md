# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project purpose

This is a school project (BBW Modul 183) demonstrating OWASP Top 10 risks in a small
Spring Boot file-upload portal. It is deliberately structured to showcase specific
vulnerabilities/countermeasures for a grading rubric — code comments and structure
often exist *to make a security concept visible*, not just to solve a problem. Keep
this teaching intent in mind when refactoring: don't remove the deliberate before/after
demo hooks described below unless asked.

The primary risk demonstrated is **A08:2025 Software or Data Integrity Failures**
(SHA-256 verification of uploaded files on write and read). Two more are layered in
the same app: **A01 Broken Access Control** (ownership checks / IDOR prevention) and
**A03 Software Supply Chain** (OWASP Dependency-Check at build time, not request time).

## Commands

```bash
mvn spring-boot:run                                  # run the app -> http://localhost:8080/login
mvn -B clean package                                 # build (used in CI)
mvn org.owasp:dependency-check-maven:check           # A03 demo: scan deps, report at target/dependency-check-report.html
```

There is no test source set (`src/test` does not exist) — do not assume `mvn test` exercises anything.

Demo accounts (seeded by `config/DataInitializer.java`, in-memory H2, recreated on every restart):
- `user` / `user12345` — ROLE_USER
- `admin` / `admin12345` — ROLE_ADMIN

## Architecture

Packages are organized by domain, not by layer: `security/`, `file/`, `user/`, `web/`, `config/`.

Request path (simplified filter chain, see `security/SecurityConfig.java`):

```
HTTP -> CorsFilter -> CsrfFilter -> RateLimitFilter (custom) ->
        UsernamePasswordAuthenticationFilter (form login, lockout) ->
        AuthorizationFilter (ROLE_*) -> Controller -> Service -> Repository -> H2
```

Key pieces and why they exist:

- **`file/FileService.java`** — the core of the A08 story. `store()` does content-based
  MIME detection via Apache Tika (client-supplied `Content-Type` is ignored), a
  filename-extension deny-list as a second barrier, and computes a SHA-256 anchor
  before writing the blob to `app.storage-dir` (`./data/uploads/<random-uuid>`, filename
  never trusted for the on-disk path). `load()` re-hashes on every read and re-checks
  ownership; a mismatch throws `IntegrityException`, an ownership violation throws
  `AccessDeniedException` — both paths are audit-logged. The DB (`FileEntity`) only
  holds metadata + hash, never the blob content, so tampering with the blob file on
  disk is exactly what triggers the integrity-failure demo.
- **`security/SecurityConfig.java`** — CSRF is intentionally left ON (session-cookie
  form login), CORS is an explicit allowlist (not `*`), and `anyRequest().authenticated()`
  is the default-deny baseline. The H2 console (`/h2-console/**`) and a relaxed CSP for
  it are marked **DEV-only** and must be removed before any real deployment (A02
  Security Misconfiguration) — don't "fix" them without flagging that tradeoff.
- **`security/RateLimitFilter.java`** + **`security/LoginAttemptService.java`** —
  two independent throttles: a Bucket4j per-IP bucket ahead of the auth filter (blocks
  brute force before a password is even checked), and a per-username lockout after N
  failed attempts (`app.login.max-attempts` / `app.login.lock-minutes` in
  `application.yml`). Both are in-memory `ConcurrentHashMap`s — fine for this single-instance
  demo, explicitly not cluster-safe.
- **`security/SecurityAuditLogger.java`** — structured key=value audit logging for
  security-relevant events (upload, download, access-denied, integrity-violation,
  rate-limited). Never log secrets/PII here.
- **`web/GlobalExceptionHandler.java`** — the A10 (Mishandling of Exceptional
  Conditions) bonus: generic error bodies to the client, full stack traces only to the
  server log. Follow this pattern for any new exception types — never let a raw
  exception message or trace reach the HTTP response.
- **`web/FileController.java`** — `allFiles()` under `/admin/files` is a known
  placeholder (calls `listOwn("")` instead of a real `repository.findAll()`); it exists
  to demonstrate `@PreAuthorize` method-security layered on top of the URL-based
  `/admin/**` rule, not as a finished feature.
- **`pom.xml`** — the commented-out `commons-collections:3.2.1` dependency block is a
  deliberate, opt-in A03 demo (CVE-2015-7501). It's meant to be uncommented temporarily
  to show `dependency-check-maven` catching it, then re-commented — don't "clean it up"
  by deleting it.
- **`.gitlab-ci.yml`** — two stages: `build` (`mvn package`) and `security`
  (`dependency-check-maven:check`, needs `NVD_API_KEY` CI variable, `allow_failure: false`).

## Known intentional gaps (do not "fix" silently)

- CAPTCHA is only hooked into `login.html`, not actually implemented.
- `LoginAttemptService` and `RateLimitFilter` state is in-memory and per-instance.
- `FileController.allFiles()` is a placeholder, not a real admin listing.

If asked to address any of the above, treat it as a real feature request and confirm
scope first — these are documented as known scope limitations in the README, not bugs.
