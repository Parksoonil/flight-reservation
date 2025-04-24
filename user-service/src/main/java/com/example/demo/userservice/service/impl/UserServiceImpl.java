package com.example.demo.userservice.service.impl;

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
    public UserEntity createUser(UserEntity user) {
        return userRepository.save(user);
    }

    @Override
    public UserEntity updateUser(Long id, UserEntity userDetails) {
        return userRepository.findById(id).map(user -> {
            user.setUserFirstName(userDetails.getUserFirstName());
            user.setUserLastName(userDetails.getUserLastName());
            user.setEmail(userDetails.getEmail());
            user.setPhone(userDetails.getPhone());
            user.setBirthday(userDetails.getBirthday());
            user.setAddress(userDetails.getAddress());
            return userRepository.save(user);
        }).orElseThrow(() -> new RuntimeException("User Not Found"));
    }

    @Override
    public boolean deleteUser(Long id) {
        return userRepository.findById(id).map(user -> {
            userRepository.delete(user);
            return true;
        }).orElse(false);
    }
}
