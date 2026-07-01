package ch.bbw.owasp.security;

import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;

/**
 * A06/A07: simple self-hosted arithmetic CAPTCHA (no external service/API key
 * needed). The expected answer lives server-side in the HTTP session and is
 * consumed on first use, so a bot cannot replay a solved challenge.
 */
@Service
public class CaptchaService {

    private static final String SESSION_ANSWER_ATTR = "captchaAnswer";

    private final SecureRandom random = new SecureRandom();

    public record Challenge(String question) {
    }

    public Challenge generate(HttpSession session) {
        int a = 1 + random.nextInt(9);
        int b = 1 + random.nextInt(9);
        session.setAttribute(SESSION_ANSWER_ATTR, a + b);
        return new Challenge(a + " + " + b + " = ?");
    }

    /** One-time use: the stored answer is removed whether or not it matches. */
    public boolean verify(HttpSession session, String submittedAnswer) {
        Object expected = session.getAttribute(SESSION_ANSWER_ATTR);
        session.removeAttribute(SESSION_ANSWER_ATTR);
        if (expected == null || submittedAnswer == null) {
            return false;
        }
        try {
            return ((Integer) expected).intValue() == Integer.parseInt(submittedAnswer.trim());
        } catch (NumberFormatException e) {
            return false;
        }
    }
}
