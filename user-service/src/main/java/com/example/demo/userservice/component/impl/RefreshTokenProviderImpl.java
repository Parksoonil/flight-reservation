package com.example.demo.userservice.component.impl;

import com.example.demo.userservice.component.TokenProvider;
import com.example.demo.userservice.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component("refreshTokenProvider")
public class RefreshTokenProviderImpl implements TokenProvider {

    // 리프래시 토큰은 보통 액세스 토큰보다 훨씬 긴 유효기간을 갖습니다 (예: 7일)
    private final Key jwtSecret = Keys.secretKeyFor(SignatureAlgorithm.HS512);
    private final long validityInMillis = 7 * 24 * 60 * 60 * 1000; // 7일
    private final UserRepository userRepository;

    public RefreshTokenProviderImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public String createToken(String email) {
        // refresh token은 일반적으로 최소한의 정보만 포함할 수 있습니다.
        Claims claims = Jwts.claims().setSubject(email);
        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMillis);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    @Override
    public long getValidityInMillis() {
        return validityInMillis;
    }

    @Override
    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public String getEmailFromToken(String token) {
        return Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    @Override
    public Claims getClaimsFromToken(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(jwtSecret) // 비밀키를 바이트 배열로 전달
                .parseClaimsJws(token)
                .getBody();
        return claims;
    }
}