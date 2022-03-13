package com.exp.securityjwt.rest;

import com.exp.securityjwt.domain.JwtUser;
import com.exp.securityjwt.service.JwtService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@RestController
@RequestMapping("/auth")
//@PreAuthorize("hasRole('ROLE_GUEST')") // hasRole需要带前缀写法 ROLE_xxxx 同时userDetails的权限里也有ROLE_xxxx
//@PreAuthorize("hasAuthority('auth')") // userDetails包含auth就行
public class AuthController {

    @Autowired
    protected JwtService jwtService;

    private final List<String> auths = Collections.singletonList("guest");

    @PostMapping("/login")
    public ResponseEntity<Object> login() {
        try {
            // 初始化token
            JwtUser user = JwtUser.builder()
                    .username("user")
                    .authorities(auths.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()))
                    .build();
            return ResponseEntity.ok(jwtService.create(user));
        } catch (Exception e) {
            log.error(e.getLocalizedMessage(), e);
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
    }

}
