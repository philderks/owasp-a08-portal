package ch.bbw.owasp.security;

import ch.bbw.owasp.user.AppUser;
import ch.bbw.owasp.user.AppUserRepository;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class AppUserDetailsService implements UserDetailsService {

    private final AppUserRepository users;
    private final LoginAttemptService loginAttemptService;

    public AppUserDetailsService(AppUserRepository users,
                                 LoginAttemptService loginAttemptService) {
        this.users = users;
        this.loginAttemptService = loginAttemptService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        AppUser u = users.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("unknown user"));

        boolean locked = loginAttemptService.isBlocked(username);

        return User.withUsername(u.getUsername())
                .password(u.getPasswordHash())
                .roles(u.getRole().name())     // ROLE_USER / ROLE_ADMIN
                .accountLocked(locked)         // A07: gesperrter Account -> LockedException
                .build();
    }
}
