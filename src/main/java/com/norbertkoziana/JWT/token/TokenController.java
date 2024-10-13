package com.norbertkoziana.JWT.token;

import com.norbertkoziana.JWT.model.LoginRequest;
import com.norbertkoziana.JWT.model.RegisterRequest;
import com.norbertkoziana.JWT.user.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
@RestController
@RequiredArgsConstructor
public class TokenController {

    private final TokenService tokenService;

    private final AuthenticationManager authenticationManager;

    @PostMapping("/token/new")
    public String newToken(@RequestBody LoginRequest loginRequest){
        UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated(
                loginRequest.getUsername(), loginRequest.getPassword());
        Authentication authentication = authenticationManager.authenticate(token);

        return tokenService.generateToken(authentication);
    }

    @PostMapping("/register")
    public User register(@RequestBody RegisterRequest registerRequest){
        return tokenService.registerUser(registerRequest);
    }
}
