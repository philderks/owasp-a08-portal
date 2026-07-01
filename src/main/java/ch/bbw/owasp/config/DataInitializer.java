package ch.bbw.owasp.config;

import ch.bbw.owasp.user.AppUser;
import ch.bbw.owasp.user.AppUserRepository;
import ch.bbw.owasp.user.Role;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Seeds demo accounts. In a real app these passwords would come from a secure
 * provisioning step, never hard-coded. Fine for a local Modul-183 demo.
 *   user  / user12345
 *   admin / admin12345
 */
@Configuration
public class DataInitializer {

    @Bean
    CommandLineRunner seedUsers(AppUserRepository users, PasswordEncoder encoder) {
        return args -> {
            if (users.findByUsername("user").isEmpty()) {
                users.save(new AppUser("user", encoder.encode("user12345"), Role.USER));
            }
            if (users.findByUsername("admin").isEmpty()) {
                users.save(new AppUser("admin", encoder.encode("admin12345"), Role.ADMIN));
            }
        };
    }
}
