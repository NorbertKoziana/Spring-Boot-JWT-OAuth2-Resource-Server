package com.norbertkoziana.JWT.user;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
@RestController
public class UserController {
    @GetMapping("/hello")
    public String home(Principal principal) {
        return "Hello, " + principal.getName();
    }
}
