package com.example.demo.userservice.service.impl;

import com.example.demo.userservice.dto.UserUpdateDTO;
import com.example.demo.userservice.entity.UserEntity;
import com.example.demo.userservice.repository.UserRepository;
import com.example.demo.userservice.service.UserService;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    public UserServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public List<UserEntity> findAll() {
        return userRepository.findAll();
    }

    @Override
    public Optional<UserEntity> findById(Long id) {
        return userRepository.findById(id);
    }

    @Override
    public Optional<UserEntity> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    @Override
    public Optional<UserEntity> updatePass(String email, String password) {
        return Optional.empty();
    }

    @Override
    public String findIdByPhone(String phone) {
        return userRepository.findByPhone(phone)
                .map(UserEntity::getEmail)
                .orElse(null);
    }

    @Override
    public boolean resetPassword(String email, String newPassword) {
        Optional<UserEntity> optionalUser = userRepository.findByEmail(email);
        if (optionalUser.isEmpty()) {
            return false;
        }
        UserEntity user = optionalUser.get();
        user.setPassword(newPassword);
        userRepository.save(user);
        return true;
    }

    @Override
    public UserEntity createUser(UserEntity user) {
        return userRepository.save(user);
    }

    @Override
    public UserEntity updateUser(UserEntity user, UserUpdateDTO userDTO) {
        user.setUserFirstName(userDTO.getUserFirstName());
        user.setUserLastName(userDTO.getUserLastName());
        user.setPhone(userDTO.getPhone());
        user.setBirthday(userDTO.getBirthday());
        user.setAddress(userDTO.getAddress());
        return userRepository.save(user);
    }

    @Override
    public boolean deleteUser(Long id) {
        return userRepository.findById(id).map(user -> {
            userRepository.delete(user);
            return true;
        }).orElse(false);
    }
}
