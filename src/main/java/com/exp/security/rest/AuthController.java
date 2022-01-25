package com.exp.security.rest;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@PreAuthorize("hasRole('ROLE_GUEST')") // hasRole需要带前缀写法 ROLE_xxxx 同时userDetails的权限里也有ROLE_xxxx
//@PreAuthorize("hasAuthority('auth')") // userDetails包含auth就行
public class AuthController {

    @GetMapping("")
    public String hello() {
        return "hello";
    }

}
