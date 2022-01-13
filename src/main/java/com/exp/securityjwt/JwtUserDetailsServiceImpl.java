package com.exp.securityjwt;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Arrays;

public class JwtUserDetailsServiceImpl implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 从数据查出user
        User user = new User();
        user.setName(username);
        user.setPassword("123456");
        user.setAuthorities(Arrays.asList("ADMIN", "TEST"));
        return JwtUserFactory.create(user);
    }
}