package com.example.demo.userservice.service.impl;

import com.example.demo.userservice.component.TokenProvider;
import com.example.demo.userservice.dto.LoginRequest;
import com.example.demo.userservice.entity.UserEntity;
import com.example.demo.userservice.exception.AuthException;
import com.example.demo.userservice.service.AuthService;
import com.example.demo.userservice.service.UserService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

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


        // 액세스, 리프래시 토큰 생성
        String accessToken = accessTokenProvider.createToken(user.getEmail());
        String refreshToken = refreshTokenProvider.createToken(user.getEmail());
        System.out.println("Access token: " + accessToken);
        System.out.println("Refresh token: " + refreshToken);

        // Redis에 토큰 저장 (TTL은 각 토큰의 유효기간을 밀리초 단위로 사용)
        ValueOperations<String, Object> ops = redisTemplate.opsForValue();
        ops.set(accessToken, user, accessTokenProvider.getValidityInMillis(), TimeUnit.MILLISECONDS);
        ops.set(refreshToken, user, refreshTokenProvider.getValidityInMillis(), TimeUnit.MILLISECONDS);
        System.out.println(ops.get(accessToken));
        System.out.println(ops.get(refreshToken));


        // HTTPOnly 쿠키 설정 (리프래시 토큰)
        Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge((int) (refreshTokenProvider.getValidityInMillis() / 1000));

        System.out.println(refreshTokenCookie.getValue());

        // 응답 객체에 쿠키 추가
        response.addCookie(refreshTokenCookie);

        // 클라이언트로 반환할 응답 데이터 구성
        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("accessToken", accessToken);
        return responseBody;
    }

    public String logout(HttpServletRequest request, HttpServletResponse response) {
        // 1. Authorization 헤더에서 Bearer 토큰 추출
        String accessToken = resolveToken(request);
        System.out.println("Access token: " + accessToken);
        if (accessToken == null || !accessTokenProvider.validateToken(accessToken)) {
            throw new AuthException("Invalid token", HttpStatus.BAD_REQUEST);
        }
        System.out.println(accessToken);
        // 2. Redis에서 액세스 및 refresh 토큰 삭제
        Boolean accessDeleted = redisTemplate.delete(accessToken);
        Boolean refreshDeleted = redisTemplate.delete(getRefreshTokenFromCookies(request));
        System.out.println("Access deleted: " + accessDeleted);
        System.out.println("Refresh deleted: " + refreshDeleted);
        if (Boolean.TRUE.equals(accessDeleted) && Boolean.TRUE.equals(refreshDeleted)) {
            // 3. HTTP 요청의 쿠키에서 refreshToken 쿠키 삭제 처리
            Cookie refreshTokenCookie = new Cookie("refreshToken", "");
            refreshTokenCookie.setPath("/");
            refreshTokenCookie.setMaxAge(0);
            response.addCookie(refreshTokenCookie);

            return "Logout successful";
        } else {
            throw new AuthException("Invalid token", HttpStatus.BAD_REQUEST);
        }
    }

    private String getRefreshTokenFromCookies(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        System.out.println(cookies);
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                System.out.println(cookie);
                if ("refreshToken".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    // Authorization 헤더에서 토큰 정보 추출 (Bearer 토큰)
    public String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
    /**
     * HTTPOnly 쿠키에 저장된 refresh 토큰을 검증 후, 새로운 액세스 토큰을 발급합니다.
     *
     * @param refreshToken 클라이언트로부터 전달받은 refresh 토큰 (쿠키로 전달됨)
     * @return 새롭게 발급된 액세스 토큰
     * @throws ResponseStatusException refresh 토큰이 없거나 유효하지 않을 경우 예외 발생 (401)
     */
    public String refreshAccessToken(String refreshToken) {
        // refresh 토큰이 없으면 401 에러 발생
        if (refreshToken == null || refreshToken.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Refresh token is missing");
        }

        // refresh 토큰 유효성 검사
        if (!refreshTokenProvider.validateToken(refreshToken)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid refresh token");
        }

        // 토큰에서 클레임 추출
        Claims claims = refreshTokenProvider.getClaimsFromToken(refreshToken);
        String email = claims.getSubject();

        Optional<UserEntity> userOptional = userService.findByEmail(email);
        if (userOptional.isEmpty()) {
            throw new AuthException("Invalid email", HttpStatus.UNAUTHORIZED);
        }

        String accessToken = accessTokenProvider.createToken(email);
        ValueOperations<String, Object> ops = redisTemplate.opsForValue();
        UserEntity user = userOptional.get();

        ops.set(accessToken, user, accessTokenProvider.getValidityInMillis(), TimeUnit.MILLISECONDS);
        // 새 액세스 토큰 생성 및 반환
        return accessToken;
    }
}
