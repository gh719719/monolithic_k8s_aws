package com.example.monolithic.user.provider;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtProvider {
    @Value("${jwt.secret}")
    private String secret;

    private final long ACCESS_TOKEN_EXPIRY = 1000L * 60 * 30;   // 30분
    private final long REFRESH_TOKEN_EXPIRY = 1000L * 60 * 60 * 24 * 7; // 7일

    // 키에 서명, 이 키들을 관리
    private Key getStringKey() {
        System.out.println(">>>> Provider JWT Secret: " + secret);
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }
    // access token provider
    public String createAT(String email) {
        System.out.println(">>>> Provider createAT: " + email);
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 30))
                .signWith(getStringKey())
                .compact();
    }

    // refresh token provider
    public String createRT(String email) {
        System.out.println(">>>> Provider createRT: " + email);
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 7))
                .signWith(getStringKey())
                .compact();
    }

    // token에서 subject 추출
    // Bearer XXXXX
    public String getUserEmailFromToken(String token) {
        System.out.println(">>>> Provider getUserEmailFromToken token: " + token);
        if(token.startsWith("Bearer ")) {
            token = token.substring(7);
        }
        // 이 안에 email 들어있음
        Claims claims = Jwts.parser()
                            .setSigningKey(getStringKey())
                            .parseClaimsJws(token)
                            .getBody();
        return claims.getSubject();
    }

    public long getATE() {
        return ACCESS_TOKEN_EXPIRY;
    }

    public long getRTE() {
        return REFRESH_TOKEN_EXPIRY;
    }
}
