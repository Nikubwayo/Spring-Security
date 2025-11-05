package org.example.security;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class MainController {

    @GetMapping("/")
    public String home() {
        return "index";
    }

    @GetMapping("/dashboard")
    public String dashboard() {
        return "dashboard";
    }

    @GetMapping("/admin/panel")
    public String adminPanel() {
        return "admin";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }
    @GetMapping("/error")
    public String accessDenied() {
        return "error";
    }

}
