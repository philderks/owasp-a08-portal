package ch.bbw.owasp.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * A09 Security Logging: zentrale Stelle fuer sicherheitsrelevante Events.
 * Regeln:
 *   - NIE Passwoerter, Tokens, Session-IDs oder PII loggen.
 *   - Key=Value-Format, damit Logstash/Loki es strukturiert parsen kann.
 *   - Username ist hier als Audit-Information ok; in DSGVO-Kontexten ggf. pseudonymisieren.
 */
@Component
public class SecurityAuditLogger {

    private static final Logger log = LoggerFactory.getLogger(SecurityAuditLogger.class);

    public void loginSuccess(String username) {
        log.info("event=LOGIN_SUCCESS user={}", username);
    }

    public void loginFailure(String username) {
        log.warn("event=LOGIN_FAILURE user={}", username);
    }

    public void accountLocked(String username) {
        log.warn("event=ACCOUNT_LOCKED user={}", username);
    }

    public void fileUploaded(String username, Long fileId, String sha256) {
        log.info("event=FILE_UPLOAD user={} fileId={} sha256={}", username, fileId, sha256);
    }

    public void fileDownloaded(String username, Long fileId) {
        log.info("event=FILE_DOWNLOAD user={} fileId={}", username, fileId);
    }

    public void accessDenied(String username, Long fileId) {
        log.warn("event=ACCESS_DENIED user={} fileId={}", username, fileId);
    }

    public void integrityViolation(Long fileId, String expected, String actual) {
        log.error("event=INTEGRITY_VIOLATION fileId={} expectedSha256={} actualSha256={}",
                fileId, expected, actual);
    }

    public void rateLimited(String clientIp) {
        log.warn("event=RATE_LIMITED ip={}", clientIp);
    }

    public void captchaFailed(String username) {
        log.warn("event=CAPTCHA_FAILED user={}", username);
    }
}
