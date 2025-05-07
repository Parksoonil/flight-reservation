package com.example.demo.userservice.controller;

import com.example.demo.userservice.dto.UserUpdateDTO;
import com.example.demo.userservice.entity.UserEntity;
import com.example.demo.userservice.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@PreAuthorize("hasRole('admin')")
@RestController
@RequestMapping("api/admin/users")
public class AdminUserController {

    private final UserService userService;

    public AdminUserController(UserService userService) {
        this.userService = userService;
    }
    // 모든 사용자 조회
    @GetMapping
    public List<UserEntity> findAll() {
        return userService.findAll();
    }

    // 특정 사용자 조회
    @GetMapping("/{id}")
    public ResponseEntity<UserEntity> getUserById(@PathVariable Long id) {
        return userService.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    // 사용자 생성
    @PostMapping
    public UserEntity createUser(@RequestBody UserEntity user) {
        return userService.createUser(user);
    }

    // 사용자 수정
    @PutMapping("/{id}")
    public ResponseEntity<UserEntity> updateUser(@PathVariable Long id, @RequestBody UserEntity user) {
        try {
            UserUpdateDTO userDTO = new UserUpdateDTO();
            userDTO.setUserLastName(user.getUserLastName());
            userDTO.setUserFirstName(user.getUserFirstName());
            userDTO.setPhone(user.getPhone());
            userDTO.setBirthday(user.getBirthday());
            userDTO.setAddress(user.getAddress());

            Optional<UserEntity> user2 = userService.findById(id);

            UserEntity updatedUser = userService.updateUser(user2.orElse(null), userDTO);
            return ResponseEntity.ok(updatedUser);
        } catch (RuntimeException e) {
            return ResponseEntity.notFound().build();
        }
    }
    // 사용자 삭제
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }
}
