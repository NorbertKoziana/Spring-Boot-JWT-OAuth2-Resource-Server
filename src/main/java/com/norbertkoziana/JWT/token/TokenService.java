package com.norbertkoziana.JWT.token;
import com.norbertkoziana.JWT.model.RegisterRequest;
import com.norbertkoziana.JWT.user.User;
import org.springframework.security.core.Authentication;
public interface TokenService {
    public String generateToken (Authentication authentication);

    public User registerUser(RegisterRequest registerRequest);
}
