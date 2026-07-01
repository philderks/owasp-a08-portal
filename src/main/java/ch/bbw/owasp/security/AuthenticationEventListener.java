package ch.bbw.owasp.security;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

/**
 * Haengt sich an Spring Securitys Authentication-Events. Dadurch landet die
 * Lockout-Logik nicht im Controller, sondern reagiert zentral auf das, was
 * der AuthenticationManager tatsaechlich entschieden hat.
 */
@Component
public class AuthenticationEventListener {

    private final LoginAttemptService loginAttemptService;
    private final SecurityAuditLogger audit;

    public AuthenticationEventListener(LoginAttemptService loginAttemptService,
                                       SecurityAuditLogger audit) {
        this.loginAttemptService = loginAttemptService;
        this.audit = audit;
    }

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        String username = event.getAuthentication().getName();
        loginAttemptService.loginSucceeded(username);
        audit.loginSuccess(username);
    }

    @EventListener
    public void onFailure(AbstractAuthenticationFailureEvent event) {
        String username = String.valueOf(event.getAuthentication().getName());
        loginAttemptService.loginFailed(username);
        audit.loginFailure(username);
        if (loginAttemptService.isBlocked(username)) {
            audit.accountLocked(username);
        }
    }
}
