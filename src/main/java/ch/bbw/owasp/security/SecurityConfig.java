package ch.bbw.owasp.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Architektur-Aufgabe (2.3): Filter Chain, Least Privilege, CORS und CSRF.
 *
 * Reihenfolge der relevanten Filter (vereinfacht):
 *   CorsFilter -> CsrfFilter -> RateLimitFilter (custom) ->
 *   UsernamePasswordAuthenticationFilter -> AuthorizationFilter -> Controller
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity   // aktiviert @PreAuthorize fuer Method-Level Security (A01)
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        // A04: BCrypt, adaptiver Work-Factor. Niemals MD5/SHA-1/Klartext.
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           RateLimitFilter rateLimitFilter,
                                           CaptchaFilter captchaFilter) throws Exception {
        http
            .cors(Customizer.withDefaults())
            // CSRF bleibt AKTIV: wir nutzen Form-Login + Session-Cookies.
            // (Bei einer reinen Token-REST-API ohne Cookies waere ein bewusstes
            //  Deaktivieren vertretbar — hier ist es das nicht.)
            .csrf(csrf -> csrf
                .ignoringRequestMatchers("/h2-console/**"))   // nur DEV
            .headers(headers -> headers
                .frameOptions(frame -> frame.sameOrigin())    // nur fuer H2-Console (DEV)
                // A02: Security-Header
                .contentSecurityPolicy(csp -> csp.policyDirectives(
                        "default-src 'self'; img-src 'self' data:; object-src 'none'")))
            .sessionManagement(sm -> sm
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .sessionFixation(sf -> sf.changeSessionId()))
            // Least Privilege: alles geschlossen, nur Noetiges geoeffnet.
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/css/**", "/error").permitAll()
                .requestMatchers("/h2-console/**").permitAll()         // nur DEV
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated())
            .formLogin(form -> form
                .loginPage("/login")
                .defaultSuccessUrl("/files", true)
                .failureHandler(loginFailureHandler())
                .permitAll())
            .logout(logout -> logout
                .logoutSuccessUrl("/login?logout")
                .permitAll())
            // Rate-Limit und CAPTCHA VOR der Authentifizierung -> bremst
            // Credential Stuffing, bevor ueberhaupt ein Passwort geprueft wird.
            .addFilterBefore(rateLimitFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(captchaFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /** Carries the attempted username back to /login so the CAPTCHA can be shown. */
    private AuthenticationFailureHandler loginFailureHandler() {
        return (request, response, exception) -> {
            String username = request.getParameter("username");
            String encodedUser = username == null ? ""
                    : URLEncoder.encode(username, StandardCharsets.UTF_8);
            response.sendRedirect(request.getContextPath() + "/login?error&user=" + encodedUser);
        };
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration cfg = new CorsConfiguration();
        // Allowlist statt "*": nur das bekannte Frontend-Origin.
        cfg.setAllowedOrigins(List.of("https://app.example.ch"));
        cfg.setAllowedMethods(List.of("GET", "POST"));
        cfg.setAllowedHeaders(List.of("Content-Type", "X-CSRF-TOKEN"));
        cfg.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", cfg);
        return source;
    }
}
