package com.norbertkoziana.JWT.token;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
@RestController
@RequiredArgsConstructor
public class TokenController {

    private final TokenService tokenService;

    @PostMapping("/token/new")
    public String newToken(Authentication authentication){
        return tokenService.generateToken(authentication);
    }
}
