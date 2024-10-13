package com.norbertkoziana.JWT.controller;

import com.norbertkoziana.JWT.user.User;
import com.norbertkoziana.JWT.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
@RestController
@RequiredArgsConstructor
public class MainController {

    private final UserRepository userRepository;

    /* Reads info from database so the data is always up-to-date */
    @GetMapping("/user/info")
    public User getUserInfo(Authentication authentication){
        return userRepository.findByUsername(authentication.getName()).orElseThrow();
    }

    /* Reads information from JWT so the data was true when the token was created and might have changed after that */
    @GetMapping("/token/info")
    public Map<String, Object> getTokenInfo(@AuthenticationPrincipal Jwt token){
        return token.getClaims();
    }

    /* Reads custom claim from JWT */
    @GetMapping("/token/claim")
    public Object getTokenClaim(@AuthenticationPrincipal Jwt token){
        return token.getClaim("CustomClaim");
    }

    @GetMapping("/public")
    public String publicEndpoint(){
        return "Hello everyone!";
    }

    @GetMapping("/secured")
    public String securedEndpoint(){
        return "Hello logged-in Users!";
    }

    @GetMapping("/admin")
    public String adminEndpoint(){
        return "Hello admins!";
    }
}
