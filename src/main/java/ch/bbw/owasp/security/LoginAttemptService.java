package ch.bbw.owasp.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A07 Authentication Failures: sperrt einen Account nach zu vielen
 * Fehlversuchen. In-Memory genuegt fuer die Demo; produktiv wuerde man
 * das in Redis/DB halten, damit es ueber mehrere Instanzen hinweg greift.
 */
@Service
public class LoginAttemptService {

    private static final class Attempt {
        int count;
        Instant lockedUntil;
    }

    private final ConcurrentHashMap<String, Attempt> attempts = new ConcurrentHashMap<>();

    private final int maxAttempts;
    private final int lockMinutes;
    private final int captchaAfter;

    public LoginAttemptService(@Value("${app.login.max-attempts:5}") int maxAttempts,
                               @Value("${app.login.lock-minutes:15}") int lockMinutes,
                               @Value("${app.login.captcha-after:2}") int captchaAfter) {
        this.maxAttempts = maxAttempts;
        this.lockMinutes = lockMinutes;
        this.captchaAfter = captchaAfter;
    }

    public void loginFailed(String username) {
        Attempt a = attempts.computeIfAbsent(key(username), k -> new Attempt());
        synchronized (a) {
            a.count++;
            if (a.count >= maxAttempts) {
                a.lockedUntil = Instant.now().plus(lockMinutes, ChronoUnit.MINUTES);
            }
        }
    }

    public void loginSucceeded(String username) {
        attempts.remove(key(username));
    }

    public boolean isBlocked(String username) {
        Attempt a = attempts.get(key(username));
        if (a == null || a.lockedUntil == null) {
            return false;
        }
        if (Instant.now().isAfter(a.lockedUntil)) {
            attempts.remove(key(username));   // Sperre abgelaufen
            return false;
        }
        return true;
    }

    /** A06/A07: after a few failed attempts, force a CAPTCHA before the next try. */
    public boolean requiresCaptcha(String username) {
        Attempt a = attempts.get(key(username));
        return a != null && a.count >= captchaAfter && !isBlocked(username);
    }

    private String key(String username) {
        return username == null ? "" : username.toLowerCase();
    }
}
