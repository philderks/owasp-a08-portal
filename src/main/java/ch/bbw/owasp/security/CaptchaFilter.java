package ch.bbw.owasp.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * A06/A07: once a username has enough recent failed attempts
 * ({@link LoginAttemptService#requiresCaptcha}), the CAPTCHA must be solved
 * correctly BEFORE the request reaches the AuthenticationManager — verifying
 * it only after authentication would let a bot brute-force the password while
 * ignoring the CAPTCHA entirely.
 */
@Component
public class CaptchaFilter extends OncePerRequestFilter {

    private final LoginAttemptService loginAttemptService;
    private final CaptchaService captchaService;
    private final SecurityAuditLogger audit;

    public CaptchaFilter(LoginAttemptService loginAttemptService,
                         CaptchaService captchaService,
                         SecurityAuditLogger audit) {
        this.loginAttemptService = loginAttemptService;
        this.captchaService = captchaService;
        this.audit = audit;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !("POST".equalsIgnoreCase(request.getMethod())
                && "/login".equals(request.getServletPath()));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String username = request.getParameter("username");

        if (loginAttemptService.requiresCaptcha(username)) {
            String submitted = request.getParameter("captcha");
            if (!captchaService.verify(request.getSession(), submitted)) {
                audit.captchaFailed(username);
                String encodedUser = username == null ? ""
                        : URLEncoder.encode(username, StandardCharsets.UTF_8);
                response.sendRedirect(request.getContextPath() + "/login?error&user=" + encodedUser);
                return;
            }
        }

        chain.doFilter(request, response);
    }
}
