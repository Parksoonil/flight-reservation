package com.example.demo.userservice.component;

import java.time.LocalDate;
import java.time.LocalDateTime;

import com.example.demo.userservice.entity.UserEntity;
import com.example.demo.userservice.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Autowired;

@Component
public class TestDataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;

    @Autowired
    public TestDataInitializer(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public void run(String... args) throws Exception {
        // 기존에 동일한 이메일을 가진 사용자가 없는지 확인하여 중복 생성 방지
        if (!userRepository.existsByEmail("admin@example.com")) {
            UserEntity adminUser = new UserEntity();
            adminUser.setUserFirstName("Admin");
            adminUser.setUserLastName("User");

            // 실제 운영환경에서는 반드시 안전한 암호화 알고리즘(예: BCrypt)을 사용하여 비밀번호를 저장하세요.
            adminUser.setPassword("admin1234");

            adminUser.setEmail("admin@example.com");
            adminUser.setPhone("01000000000");

            // 테스트용 생일 설정 (예: 1990-01-01)
            adminUser.setBirthday(LocalDate.of(1990, 1, 1));

            // 계정 생성 시각은 시스템 현재 시간으로 설정
            adminUser.setCreatedAt(LocalDateTime.now());

            adminUser.setAddress("Test Address");

            // admin 권한 지정
            adminUser.setAdmin(true);

            userRepository.save(adminUser);
            System.out.println("Admin 테스트 계정이 생성되었습니다.");
        }
    }
}