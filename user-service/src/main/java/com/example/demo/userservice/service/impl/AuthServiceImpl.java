package com.example.demo.userservice.service.impl;

import com.example.demo.userservice.component.TokenProvider;
import com.example.demo.userservice.dto.LoginRequest;
import com.example.demo.userservice.entity.UserEntity;
import com.example.demo.userservice.exception.AuthException;
import com.example.demo.userservice.service.AuthService;
import com.example.demo.userservice.service.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.TimeUnit;

@Service
public class AuthServiceImpl implements AuthService {

    private final UserService userService;
    private final TokenProvider accessTokenProvider;
    private final TokenProvider refreshTokenProvider;
    private final RedisTemplate<String, Object> redisTemplate;

    public AuthServiceImpl(UserService userService,
                       @Qualifier("accessTokenProvider") TokenProvider accessTokenProvider,
                       @Qualifier("refreshTokenProvider") TokenProvider refreshTokenProvider,
                       RedisTemplate<String, Object> redisTemplate) {
        this.userService = userService;
        this.accessTokenProvider = accessTokenProvider;
        this.refreshTokenProvider = refreshTokenProvider;
        this.redisTemplate = redisTemplate;
    }

    public Map<String, Object> login(LoginRequest loginRequest, HttpServletResponse response) {
        Optional<UserEntity> userOptional = userService.findByEmail(loginRequest.getEmail());
        if (userOptional.isEmpty()) {
            throw new AuthException("Invalid email", HttpStatus.UNAUTHORIZED);
        }
        UserEntity user = userOptional.get();
        if (!user.getPassword().equals(loginRequest.getPassword())) {
            throw new AuthException("Invalid password", HttpStatus.UNAUTHORIZED);
        }

        // 사용자에게 할당할 권한 설정 (필요한 경우 로직 확장)
        List<String> roles = Collections.singletonList("ROLE_USER");

        // 액세스, 리프래시 토큰 생성
        String accessToken = accessTokenProvider.createToken(user.getEmail(), roles);
        String refreshToken = refreshTokenProvider.createToken(user.getEmail(), roles);
        System.out.println("Access token: " + accessToken);
        System.out.println("Refresh token: " + refreshToken);

        // Redis에 토큰 저장 (TTL은 각 토큰의 유효기간을 밀리초 단위로 사용)
        ValueOperations<String, Object> ops = redisTemplate.opsForValue();
        ops.set(accessToken, user, accessTokenProvider.getValidityInMillis(), TimeUnit.MILLISECONDS);
        ops.set(refreshToken, user, refreshTokenProvider.getValidityInMillis(), TimeUnit.MILLISECONDS);
        System.out.println(ops.get(accessToken));
        System.out.println(ops.get(refreshToken));

        // HTTPOnly 쿠키 설정 (액세스 토큰)
        Cookie accessTokenCookie = new Cookie("accessToken", accessToken);
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setPath("/");
        accessTokenCookie.setMaxAge((int) (accessTokenProvider.getValidityInMillis() / 1000)); // 초 단위

        // HTTPOnly 쿠키 설정 (리프래시 토큰)
        Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge((int) (refreshTokenProvider.getValidityInMillis() / 1000));
        System.out.println(accessTokenCookie.getValue());
        System.out.println(refreshTokenCookie.getValue());

        // 응답 객체에 쿠키 추가
        response.addCookie(accessTokenCookie);
        response.addCookie(refreshTokenCookie);

        // 클라이언트로 반환할 응답 데이터 구성
        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("accessToken", accessToken);
        responseBody.put("refreshToken", refreshToken);
        responseBody.put("user", user);

        return responseBody;
    }

    public String logout(HttpServletRequest request) {
        // Authorization 헤더에서 Bearer 토큰 추출
        String token = resolveToken(request);
        if (token == null || !accessTokenProvider.validateToken(token)) {
            throw new AuthException("Invalid token", HttpStatus.BAD_REQUEST);
        }

        // Redis에서 토큰 삭제 (로그아웃 처리)
        Boolean deleted = redisTemplate.delete(token);
        if (Boolean.TRUE.equals(deleted)) {
            return "Logout successful";
        } else {
            throw new AuthException("Invalid token", HttpStatus.BAD_REQUEST);
        }
    }

    // Authorization 헤더에서 토큰 정보 추출 (Bearer 토큰)
    public String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
