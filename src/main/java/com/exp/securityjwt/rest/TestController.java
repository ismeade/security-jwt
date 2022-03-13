package com.exp.securityjwt.rest;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/test")
//@PreAuthorize("hasAuthority('test')") // userDetails包含auth就行
@PreAuthorize("isAuthenticated()")
public class TestController {

    @GetMapping("")
    public String test() {
        return "hello";
    }
}
