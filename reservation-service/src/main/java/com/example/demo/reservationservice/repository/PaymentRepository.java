package com.example.demo.reservationservice.repository;

import com.example.demo.reservationservice.entitiy.Payment;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.time.LocalDateTime;
import java.util.Optional;

public interface PaymentRepository extends JpaRepository<Payment, Long> {

    // ✅ 최근 3일 내의 PENDING 결제 1건 조회
    @Query("SELECT p FROM Payment p WHERE p.uId = :uId AND p.rId = :rId AND p.status = :status AND p.createdAt > :cutoff ORDER BY p.createdAt DESC")
    Optional<Payment> findFirstRecentByStatus(Long uId, Long rId, String status, LocalDateTime cutoff);

    // ✅ 가장 최근 결제 한 건 조회 (상태 관계없이)
    @Query("SELECT p FROM Payment p WHERE p.uId = :uId AND p.rId = :rId ORDER BY p.createdAt DESC")
    Optional<Payment> findLatestByUIdAndRId(Long uId, Long rId);
}

