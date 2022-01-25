package com.exp.security.config;

import com.exp.security.domain.JwtUserFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


/**
 * 过滤每次请求中的token
 */
@Slf4j
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        // 获取jwt token
        String authHeader = request.getHeader("Authorization");
        log.info("Authorization: {}", authHeader);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            final String authToken = authHeader.substring("Bearer ".length());
            // 验证解析jwt
//            jwtTokenUtil.getUsernameFromToken(authToken);
            // 将jwt转成 UserDetails

            // 将转化的UserDetails放入 SecurityContextHolder.getContext().setAuthentication(authentication)
            if ("admin".equals(authToken) && SecurityContextHolder.getContext().getAuthentication() == null) {

                UserDetails userDetails = JwtUserFactory.create(authToken);
                log.info("userDetails: {}", userDetails.getAuthorities());
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        chain.doFilter(request, response);
    }
}
