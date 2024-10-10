package com.norbertkoziana.JWT.user;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
@RestController
public class UserController {
    @GetMapping("/user/info")
    public Principal getUserInfo(Principal principal){
        return principal;
    }

}
