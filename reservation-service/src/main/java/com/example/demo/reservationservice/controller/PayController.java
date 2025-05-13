package com.example.demo.reservationservice.controller;

import com.example.demo.reservationservice.dto.PaymentStatusResponse;
import com.example.demo.reservationservice.entitiy.Payment;
import com.example.demo.reservationservice.entitiy.Reservation;
import com.example.demo.reservationservice.repository.PaymentRepository;
import com.example.demo.reservationservice.repository.ReservationRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/reservations/payments")
@RequiredArgsConstructor
public class PayController {

    private final PaymentRepository paymentRepository;
    private final ReservationRepository reservationRepository;

    /**
     * 단일 예매(rId) 결제 생성
     */
    @PostMapping("/virtual/{rId}")
    public ResponseEntity<Payment> virtualPayment(@PathVariable Long rId,
                                                  @RequestParam Long uId) {
        Optional<Reservation> opt = reservationRepository.findByRId(rId);
        if (opt.isEmpty()) return ResponseEntity.notFound().build();

        Reservation reservation = opt.get();
        if (!reservation.getUId().equals(uId)) return ResponseEntity.status(403).build();
        if (reservation.getPayment() != null) return ResponseEntity.ok(reservation.getPayment());

        Payment payment = Payment.builder()
                .uId(uId)
                .price(reservation.getTicketPrice())
                .status("PENDING")
                .createdAt(LocalDateTime.now())
                .build();

        Payment saved = paymentRepository.save(payment);
        reservation.setPayment(saved);
        reservationRepository.save(reservation);

        return ResponseEntity.ok(saved);
    }

    /**
     * 그룹 예매(groupId + uId) 전체 결제 생성
     */
    @PostMapping("/virtual/by-group")
    public ResponseEntity<Payment> virtualPaymentByGroup(@RequestParam Long uId,
                                                         @RequestParam String groupId) {
        List<Reservation> reservations = reservationRepository.findByUIdAndGroupIdAndPaymentIsNull(uId, groupId);
        if (reservations.isEmpty()) return ResponseEntity.badRequest().build();

        int totalPrice = reservations.stream().mapToInt(Reservation::getTicketPrice).sum();

        Payment payment = Payment.builder()
                .uId(uId)
                .price(totalPrice)
                .status("PENDING")
                .createdAt(LocalDateTime.now())
                .build();

        Payment saved = paymentRepository.save(payment);

        for (Reservation r : reservations) r.setPayment(saved);
        reservationRepository.saveAll(reservations);

        return ResponseEntity.ok(saved);
    }

    /**
     * 결제 상태 조회
     */
    @GetMapping("/status/{paymentId}")
    public ResponseEntity<PaymentStatusResponse> getPaymentStatus(@PathVariable Long paymentId) {
        Optional<Payment> paymentOpt = paymentRepository.findById(paymentId);
        if (paymentOpt.isEmpty()) return ResponseEntity.ok(new PaymentStatusResponse("NONE"));

        return ResponseEntity.ok(new PaymentStatusResponse(paymentOpt.get().getStatus()));
    }

    /**
     * 결제에 연결된 예매 목록 조회
     */
    @GetMapping("/{paymentId}/reservations")
    public ResponseEntity<List<Reservation>> getReservationsByPayment(@PathVariable Long paymentId) {
        List<Reservation> reservations = reservationRepository.findByPaymentId(paymentId);
        return ResponseEntity.ok(reservations);
    }

    /**
     * 단일 예매 삭제 (생성 후 3일 이내, 결제 여부 무관)
     */
    @DeleteMapping("/reservation/{rId}")
    public ResponseEntity<?> deleteSingleReservation(@PathVariable Long rId) {
        Optional<Reservation> opt = reservationRepository.findByRId(rId);
        if (opt.isEmpty()) return ResponseEntity.notFound().build();

        Reservation reservation = opt.get();
        if (reservation.getRDate().isBefore(LocalDateTime.now().minusDays(3))) {
            return ResponseEntity.status(403).body("삭제는 생성 후 3일 이내만 가능합니다.");
        }

        Payment payment = reservation.getPayment();
        reservationRepository.deleteByRId(rId);

        if (payment != null) {
            List<Reservation> linked = reservationRepository.findByPaymentId(payment.getPaymentId());
            if (linked.isEmpty()) {
                paymentRepository.deleteById(payment.getPaymentId());
            }
        }

        return ResponseEntity.noContent().build();
    }

    /**
     * 그룹 예매 일괄 삭제 (생성 후 3일 이내)
     */
    @DeleteMapping("/reservations/by-group")
    public ResponseEntity<?> deleteReservationsByGroup(@RequestParam Long uId,
                                                       @RequestParam String groupId) {
        List<Reservation> reservations = reservationRepository.findByUIdAndGroupId(uId, groupId);
        if (reservations.isEmpty()) return ResponseEntity.notFound().build();

        boolean anyExpired = reservations.stream()
                .anyMatch(r -> r.getRDate().isBefore(LocalDateTime.now().minusDays(3)));
        if (anyExpired) {
            return ResponseEntity.status(403).body("모든 예매는 생성 후 3일 이내여야 삭제 가능합니다.");
        }

        Set<Long> paymentIds = reservations.stream()
                .map(r -> r.getPayment() != null ? r.getPayment().getPaymentId() : null)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());

        for (Reservation r : reservations) {
            reservationRepository.deleteByRId(r.getRId());
        }

        for (Long pid : paymentIds) {
            List<Reservation> remains = reservationRepository.findByPaymentId(pid);
            if (remains.isEmpty()) {
                paymentRepository.deleteById(pid);
            }
        }

        return ResponseEntity.noContent().build();
    }

    /**
     * 예매 ID 목록의 결제 여부 확인
     */
    @GetMapping("/check-paid")
    public ResponseEntity<Map<Long, Boolean>> checkReservationsPaid(@RequestParam List<Long> rIds) {
        List<Reservation> reservations = reservationRepository.findAllById(rIds);

        Map<Long, Boolean> result = reservations.stream()
                .collect(Collectors.toMap(
                        Reservation::getRId,
                        r -> r.getPayment() != null
                ));

        return ResponseEntity.ok(result);
    }
}
