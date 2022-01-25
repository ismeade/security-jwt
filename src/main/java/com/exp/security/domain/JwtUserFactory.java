package com.exp.security.domain;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public final class JwtUserFactory {

    private JwtUserFactory() {}

    public static JwtUser create(String username) {

        return new JwtUser(username, "test", mapToGrantedAuthority(Arrays.asList("ROLE_GUEST", "ADMIN", "auth")));
    }

    private static List<GrantedAuthority> mapToGrantedAuthority(List<String> authorities) {
        return authorities.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
}
