package com.example.demo.userservice.controller;

import com.example.demo.userservice.component.JwtTokenProvider;
import com.example.demo.userservice.dto.LoginRequest;
import com.example.demo.userservice.entity.UserEntity;
import com.example.demo.userservice.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("api/users")
public class UserController {

    private final UserService userService;
    private final JwtTokenProvider jwtTokenProvider;
    private final RedisTemplate<String, Object> redisTemplate;

    public UserController(UserService userService, JwtTokenProvider jwtTokenProvider, RedisTemplate<String, Object> redisTemplate) {
        this.userService = userService;
        this.jwtTokenProvider = jwtTokenProvider;
        this.redisTemplate = redisTemplate;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        Optional<UserEntity> userOptional = userService.findByEmail(loginRequest.getEmail());
        if(userOptional.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid email");
        }
        UserEntity user = userOptional.get();
        if(!user.getPassword().equals(loginRequest.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid password");
        }
        List<String> roles = Collections.singletonList("ROLE_USER");
        String token = jwtTokenProvider.createToken(user.getEmail(), roles);

        ValueOperations<String, Object> ops = redisTemplate.opsForValue();
        ops.set(token, user, jwtTokenProvider.getValidityInSeconds(), TimeUnit.MILLISECONDS);

        Map<String, Object> response = new HashMap<>();
        response.put("token", token);
        response.put("user", user);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        String token = resolveToken(request);
        if(token == null || !jwtTokenProvider.validateToken(token)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid token");
        }
        Boolean delete = redisTemplate.delete(token);
        if(Boolean.TRUE.equals(delete)) {
            return ResponseEntity.ok("Logout successful");
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Invalid token");
        }
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    @GetMapping
    @Operation(summary = "유저 목록 조회", description = "등록된 모든 유저를 가져옵니다.")
    public ResponseEntity<List<UserEntity>> findAll() {
        List<UserEntity> users = userService.findAll();
        return ResponseEntity.ok(users);
    }

    @GetMapping("/{id}")
    @Operation(summary = "유저 ID로 유저 검색", description = "ID로 검색된 유저를 가져옵니다.")
    public ResponseEntity<UserEntity> findById(@PathVariable Long id) {
        Optional<UserEntity> user = userService.findById(id);
        return ResponseEntity.ok(user.orElse(null));
    }

    @PostMapping
    @Operation(summary = "유저 등록", description = "넘겨받은 객체로 유저를 등록합니다.")
    public ResponseEntity<UserEntity> create(@RequestBody UserEntity user) {
        UserEntity createdUser = userService.createUser(user);
        return ResponseEntity.status(201).body(createdUser);
    }

    @PutMapping("/{id}")
    @Operation(summary = "유저 수정", description = "ID에 해당하는 유저를 수정합니다.")
    public ResponseEntity<UserEntity> update(@PathVariable Long id, @RequestBody UserEntity user) {
        UserEntity updatedUser = userService.updateUser(id, user);
        return ResponseEntity.ok(updatedUser);
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "유저 삭제", description = "ID에 해당하는 유저를 삭제합니다.")
    public ResponseEntity<UserEntity> delete(@PathVariable Long id) {
        return userService.deleteUser(id) ? ResponseEntity.ok().build() : ResponseEntity.notFound().build();
    }
}
