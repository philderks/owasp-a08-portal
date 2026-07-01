package ch.bbw.owasp.web;

import ch.bbw.owasp.security.CaptchaService;
import ch.bbw.owasp.security.LoginAttemptService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class LoginController {

    private final LoginAttemptService loginAttemptService;
    private final CaptchaService captchaService;

    public LoginController(LoginAttemptService loginAttemptService, CaptchaService captchaService) {
        this.loginAttemptService = loginAttemptService;
        this.captchaService = captchaService;
    }

    @GetMapping("/login")
    public String login(@RequestParam(name = "user", required = false) String username,
                        Model model, HttpServletRequest request) {
        if (username != null && loginAttemptService.requiresCaptcha(username)) {
            model.addAttribute("captchaRequired", true);
            model.addAttribute("captchaQuestion", captchaService.generate(request.getSession()).question());
            model.addAttribute("username", username);
        }
        return "login";
    }
}
