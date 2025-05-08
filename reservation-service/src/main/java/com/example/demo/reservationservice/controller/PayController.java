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
import java.util.Optional;

@RestController
@RequestMapping("api/reservations/payments")
@RequiredArgsConstructor
public class PayController {

    private final PaymentRepository paymentRepository;
    private final ReservationRepository reservationRepository;

    @PostMapping("/virtual/{rId}")
    public ResponseEntity<Payment> virtualPayment(@PathVariable Long rId) {
        System.out.println("💻 [VIRTUAL] 가상 결제 요청: rId=" + rId);

        Optional<Reservation> opt = reservationRepository.findByRId(rId);
        if (opt.isEmpty()) {
            System.out.println("❌ [VIRTUAL] 예약 정보 없음");
            return ResponseEntity.notFound().build();
        }

        Reservation reservation = opt.get();

        // 기존 PENDING 결제 내역 확인
        Optional<Payment> existing = paymentRepository.findFirstRecentByStatus(
                reservation.getUId(),
                rId,
                "PENDING",
                LocalDateTime.now().minusDays(3)
        );

        if (existing.isPresent()) {
            System.out.println("🟡 [VIRTUAL] 기존 PENDING 결제 존재: id=" + existing.get().getPaymentId());
            return ResponseEntity.ok(existing.get());
        }

        int price = reservation.getTicketPrice();

        Payment payment = Payment.builder()
                .uId(reservation.getUId())
                .rId(rId)
                .price(price)
                .status("PENDING")
                .createdAt(LocalDateTime.now())
                .build();

        Payment saved = paymentRepository.save(payment);
        System.out.println("✅ [VIRTUAL] 결제 생성 완료: id=" + saved.getPaymentId() + ", price=" + price);
        return ResponseEntity.ok(saved);
    }

    @GetMapping("/status")
    public ResponseEntity<PaymentStatusResponse> getPaymentStatus(@RequestParam Long rId) {
        System.out.println("📡 [STATUS] 결제 상태 확인 요청: rId=" + rId);

        Optional<Reservation> opt = reservationRepository.findByRId(rId);
        if (opt.isEmpty()) {
            System.out.println("❌ [STATUS] 예약 정보 없음");
            return ResponseEntity.notFound().build();
        }

        Reservation reservation = opt.get();
        Optional<Payment> paymentOpt = paymentRepository.findLatestByUIdAndRId(
                reservation.getUId(),
                rId
        );

        if (paymentOpt.isEmpty()) {
            System.out.println("❌ [STATUS] 결제 기록 없음");
            return ResponseEntity.ok(new PaymentStatusResponse("NONE"));
        }

        String status = paymentOpt.get().getStatus();
        System.out.println("✅ [STATUS] 결제 상태: " + status);
        return ResponseEntity.ok(new PaymentStatusResponse(status));
    }

    @DeleteMapping("/{paymentId}")
    public ResponseEntity<Void> deletePayment(@PathVariable Long paymentId) {
        System.out.println("🗑️ [DELETE] 결제 삭제 요청: paymentId=" + paymentId);

        Optional<Payment> paymentOpt = paymentRepository.findById(paymentId);
        if (paymentOpt.isEmpty()) {
            System.out.println("❌ [DELETE] 결제 정보 없음");
            return ResponseEntity.notFound().build();
        }

        paymentRepository.deleteById(paymentId);
        System.out.println("✅ [DELETE] 결제 삭제 완료: paymentId=" + paymentId);
        return ResponseEntity.noContent().build();
    }

}
