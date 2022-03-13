package com.exp.securityjwt.domain;

import lombok.experimental.SuperBuilder;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

@SuperBuilder
public class JwtUser {

    private final String username;

    private final Collection<? extends GrantedAuthority> authorities;

    public JwtUser(String username, Collection<? extends GrantedAuthority> authorities) {
        this.username = username;
        this.authorities = authorities;
    }

    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    public String getUsername() {
        return this.username;
    }

}
