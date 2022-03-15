package com.exp.securityjwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity // 启用web安全检查
@EnableGlobalMethodSecurity(prePostEnabled = true) // 启用全局方法检查
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public JwtAuthenticationTokenFilter authenticationTokenFilterBean() throws Exception {
        return new JwtAuthenticationTokenFilter(authenticationManager());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()

                .addFilterBefore(authenticationTokenFilterBean(), UsernamePasswordAuthenticationFilter.class)
                // 不创建session
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()

                .authorizeRequests()
                // 鉴权接口不需要认证
                .antMatchers("/auth/**").permitAll()
                // 都需要认证 放到最后 类上的@PreAuthorize("permitAll") 无效 注释掉以后完全放开，类上必须做验证
                // TODO 不知道怎么样嫩让类上的注解优先与这边这句
//                .anyRequest().authenticated()
        ;

        http.headers()
                .frameOptions().sameOrigin()
                .cacheControl();
    }
}
