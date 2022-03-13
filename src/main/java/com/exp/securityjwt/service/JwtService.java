package com.exp.securityjwt.service;

import com.exp.securityjwt.domain.JwtUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secret;
    @Value("${jwt.exp}")
    private Long exp;

    public String create(JwtUser user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("username", user.getUsername());
        claims.put("auths", user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.toList()));
        log.info("claims: {}", claims);
        return create(claims);
    }

    private String create(Map<String, Object> claims) {
        // 下面就是在为payload添加各种标准声明和私有声明了
        return Jwts.builder() // 这里其实就是new一个JwtBuilder，设置jwt的body
                .setClaims(claims) // 如果有私有声明，一定要先设置这个自己创建的私有的声明，这个是给builder的claim赋值，一旦写在标准的声明赋值之后，就是覆盖了那些标准的声明的
                .setId(UUID.randomUUID().toString()) // 设置jti(JWT ID)：是JWT的唯一标识，根据业务需要，这个可以设置为一个不重复的值，主要用来作为一次性token,从而回避重放攻击。
                .setIssuedAt(new Date())  // iat: jwt的签发时间
                .setExpiration(new Date(System.currentTimeMillis() + (exp * 1000))) // exp: 过期时间
                .signWith(SignatureAlgorithm.HS256, generalKey()) // 设置签名使用的签名算法和签名使用的秘钥
                .compact();
    }

    private SecretKey generalKey() {
        byte[] encodedKey = Base64.encodeBase64(secret.getBytes());
        return new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
    }

    /**
     * 验证jwt
     */
    public Optional<JwtUser> verify(String jwt) {
        // 签名秘钥，和生成的签名的秘钥一模一样
        SecretKey key = generalKey();
        try {
            Claims claims = Jwts.parser() // 得到DefaultJwtParser
                    .setSigningKey(key) // 设置签名的秘钥
                    .parseClaimsJws(jwt).getBody();
            final List<?> auths = claims.get("auths", List.class);
            JwtUser userDetails = JwtUser.builder()
                    .username(claims.get("username", String.class))
                    .authorities(auths.stream().map(String.class::cast).map(SimpleGrantedAuthority::new).collect(Collectors.toList()))
                    .build();
            return Optional.of(userDetails);
        } catch (Exception e) {
            log.error(e.getLocalizedMessage(), e);
        } // 设置需要解析的jwt
        return Optional.empty();
    }


}
