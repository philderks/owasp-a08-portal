# OWASP A08 Datei-Upload-Portal — Modul 183

Spring-Boot-Applikation für das Modul-183-Projekt. Kern ist **A08:2025 — Software
or Data Integrity Failures** (Integritätsprüfung beim Datei-Upload/-Download).
Zwei weitere Risiken sind im selben Portal demonstriert, damit die geforderten
*„mindestens 3 OWASP-Risiken"* erfüllt sind:

| OWASP | Schwerpunkt | Wo im Code |
|-------|-------------|------------|
| **A08** Software/Data Integrity | SHA-256 bei Upload + Verify bei Download, Content-Type-Validierung, Reject von Executables | `file/FileService.java` |
| **A01** Broken Access Control | Ownership-Check (kein IDOR) + `@PreAuthorize` Method-Security | `file/FileService.load(...)`, `web/FileController.allFiles()` |
| **A03** Software Supply Chain | OWASP Dependency-Check im Maven-Build + CI | `pom.xml` (Plugin), `.gitlab-ci.yml` |

> A03 lebt **build-zeit**, nicht im Request-Pfad — bewusst gewählt, um zu zeigen,
> dass nicht jeder Fix im Code-Flow sitzt.

## Erfüllung der Bewertungskriterien

| Kriterium | Umsetzung |
|-----------|-----------|
| ≥3 OWASP-Risiken demonstriert | A08, A01, A03 (+ A10 als Bonus im `GlobalExceptionHandler`) |
| Gegenmassnahmen implementiert | siehe Tabelle oben + `docs/` |
| Authentifizierung & Autorisierung | Form-Login, `ROLE_USER`/`ROLE_ADMIN`, `SecurityConfig` |
| CAPTCHA / Brute-Force-Schutz | `RateLimitFilter` (Bucket4j) + `LoginAttemptService` (Lockout) + `CaptchaFilter`/`CaptchaService` (Rechenaufgabe nach N Fehlversuchen) |
| Architektur dokumentiert | Filter-Chain-Diagramm + `SecurityConfig` Kommentare |
| Logging korrekt & sicher | `SecurityAuditLogger` — key=value, keine Secrets/PII |
| Code-Qualität & Struktur | Packages nach Domäne (`security`/`file`/`user`/`web`) |
| Präsentation / Dokumentation | dieses README + `docs/*.md` |

## Build & Run

```bash
mvn spring-boot:run
# http://localhost:8080/login
```

Demo-Accounts (siehe `config/DataInitializer.java`):

| User | Passwort | Rolle |
|------|----------|-------|
| `user`  | `user12345`  | USER  |
| `admin` | `admin12345` | ADMIN |

## Demo-Drehbuch (Schwachstelle → Fix)

### A08 — Integrität
1. Lade ein gültiges PNG/PDF hoch → SHA-256 erscheint in der Liste.
2. **Schwachstelle zeigen:** stoppe die App, manipuliere die Blob-Datei unter
   `./data/uploads/<uuid>` (ein Byte ändern), starte neu, klicke *Download*.
3. **Fix greift:** der Re-Hash weicht ab → `IntegrityException`, Event
   `INTEGRITY_VIOLATION` im Log, generische 500-Antwort (kein Stacktrace).
4. **Content-Validierung:** benenne eine `.exe` in `bild.png` um und lade hoch →
   Tika erkennt den echten MIME-Typ → Ablehnung.

### A01 — Access Control
1. Als `user` eine Datei hochladen, ihre `id` notieren.
2. Als zweiter User (oder per geänderter URL `/files/<fremde-id>/download`)
   versuchen, sie zu laden → **403**, Event `ACCESS_DENIED`.
3. Als `admin` funktioniert derselbe Download (Least-Privilege-Ausnahme).

### A03 — Supply Chain
1. In `pom.xml` die auskommentierte `commons-collections 3.2.1` aktivieren.
2. `mvn org.owasp:dependency-check-maven:check` → Report unter
   `target/dependency-check-report.html`, CVE-2015-7501 sichtbar. Screenshot in die Doku.
3. Dependency entfernen/aktualisieren → Report sauber.

### A07 — Brute-Force / CAPTCHA
1. Auf `/login` zwei Mal absichtlich falsches Passwort für `user` eingeben.
2. Ab dem 3. Versuch erscheint eine Rechenaufgabe (`CaptchaService`) im Formular;
   ohne (oder mit falscher) Antwort wird der Request von `CaptchaFilter`
   **vor** dem `AuthenticationManager` abgewiesen — auch mit korrektem Passwort.
3. Nach `app.login.max-attempts` (Default 5) Fehlversuchen sperrt
   `LoginAttemptService` den Account für `app.login.lock-minutes` Minuten →
   Event `ACCOUNT_LOCKED` im Log, Login schlägt auch mit korrektem Passwort fehl.
4. Parallel: 10 schnelle POSTs auf `/login` (z. B. per Skript) → `RateLimitFilter`
   antwortet mit `429`, Event `RATE_LIMITED` im Log — pro IP, unabhängig vom Account.

## Architektur

Request-Pfad (vereinfachte Filter-Chain):

```
HTTP → CorsFilter → CsrfFilter → RateLimitFilter(custom) →
       AuthenticationFilter (Form-Login, Lockout) →
       AuthorizationFilter (ROLE_*) → Controller → Service → Repository → H2
```

- **CSRF aktiv** (Cookie-basierter Form-Login). Bewusste Entscheidung, nicht Default-Faulheit.
- **CORS** als Allowlist statt `*`.
- **Least Privilege:** `anyRequest().authenticated()`, nur `/login` + Assets offen.
- H2-Console + `csp`-Lockerung sind **DEV-only** und müssen produktiv weg (A02).

## Detail-Dokumentation

- `docs/A08-Software-Data-Integrity.md`
- `docs/A01-Broken-Access-Control.md`
- `docs/A03-Supply-Chain.md`

## Bekannte offene Punkte / Scope

- CAPTCHA ist eine einfache selbst gehostete Rechenaufgabe (kein externer
  Dienst/API-Key nötig), erscheint nach `app.login.captcha-after` Fehlversuchen
  und wird von `CaptchaFilter` server-seitig vor dem `AuthenticationManager`
  geprüft (siehe `security/CaptchaService.java`, `security/CaptchaFilter.java`).
- `LoginAttemptService` ist In-Memory → nicht cluster-fähig (für die Demo ok).
