package com.example.monolithic.common.auth;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

// Security를 사용하려면 OncePerRequestFilter를 상속받아야함
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Value("${jwt.secret}")
    private String secret;
    private Key key;
    
    @PostConstruct
    private void init() {
        System.out.println(">>>> JwtAuthenticationFilter init jwt secret : "+secret);
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }
    private final AntPathMatcher matcher = new AntPathMatcher();
    private static final List<String> WHITE_LIST_PATH = List.of(
        "/swagger-ui/**",
        "/v3/api-docs/**",
        "/users/signUp",
        "/users/signIn"
    );
    
    // 토큰없이 접근가능한 endpoint인지 아닌지 판단?
    public boolean isPath(String path) {
        return WHITE_LIST_PATH.stream()
                .anyMatch(pattern -> matcher.match(pattern, path));
    }
    
    @Override
    public void doFilterInternal(   HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {
        System.out.println(">>>> JwtAuthenticationFilter doFilter");
        HttpServletRequest req = (HttpServletRequest)request;
        HttpServletResponse res = (HttpServletResponse)response;

        String endPoint = req.getRequestURI();
        System.out.println(">>>> User EndPoint: " + endPoint);
        String method = req.getMethod();
        System.out.println(">>>> JwtAuthenticationFilter Request Method: " + method);

        if ("OPTIONS".equalsIgnoreCase(req.getMethod())) {
            res.setStatus(HttpServletResponse.SC_OK);
            res.setHeader("Access-Control-Allow-Origin", "http://localhost:3000");
            res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
            res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
            res.setHeader("Access-Control-Allow-Credentials", "true");

            chain.doFilter(request, response);
            return ;
    }

    String authHeader = req.getHeader("Authorization");
    System.out.println(">>>> JwtAuthenticationFilter Authorization: " + authHeader);
    if(authHeader == null || !authHeader.startsWith("Bearer ")) {
        System.out.println(">>>> JwtAuthenticationFilter Not Authorization: ");
        chain.doFilter(request, response);
        return  ;
    }

    String token = authHeader.substring(7);
    System.out.println(">>>> JwtAuthenticationFilter Token: "+token);
    System.out.println(">>>> JwtAuthenticationFilter token validation check ");
    try {
        // Claims == JWT 데이터
        Claims claims = Jwts.parserBuilder()
                            .setSigningKey(key)
                            .build()
                            .parseClaimsJws(token)
                            .getBody();
        String email = claims.getSubject();
        System.out.println(">>>> JwtAuthenticationFilter claims get email: " + email);        
        
        // JwtProvider 의해서 Role 입력된 경우에만 해당
        String role = claims.get("role", String.class);
        System.out.println(">>>> JwtAuthenticationFilter claims get role: " + role);

        // Spring Security 인증정보를 담는 객체 (Principal, credential, authorities)
        // UsernamePasswordAuthenticationToken
        // SecurityContextHolder

        UsernamePasswordAuthenticationToken authentication = 
            new UsernamePasswordAuthenticationToken(
                email, 
                null, 
                role != null ?
                    java.util.List.of(() -> "ROLE_"+role) : 
                    java.util.List.of()
            );
        // 사용자의 요청과 인증정보객체를 연결
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(req));

        // SecurityContext 저장 -> Ctrl 필요할 때 꺼낼 수 있음.
        // 사용자의 상태정보를 확인
        SecurityContextHolder.getContext().setAuthentication(authentication);
    } catch (Exception e) {
        e.printStackTrace();
    }

    chain.doFilter(request, response);
    }
}

