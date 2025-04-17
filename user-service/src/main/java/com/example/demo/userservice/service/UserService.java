package com.example.demo.userservice.service;

import com.example.demo.userservice.entity.UserEntity;

import java.util.List;
import java.util.Optional;

public interface UserService {
    List<UserEntity> findAll();
    Optional<UserEntity> findById(Long id);
    Optional<UserEntity> findByEmail(String email);
    UserEntity createUser(UserEntity user);
    UserEntity updateUser(Long id, UserEntity user);
    boolean deleteUser(Long id);
}
