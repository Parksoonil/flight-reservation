package com.example.demo.reservationservice.controller;

import com.example.demo.reservationservice.dto.ReservationRequestDTO;
import com.example.demo.reservationservice.dto.SeatDTO;
import com.example.demo.reservationservice.entitiy.Reservation;
import com.example.demo.reservationservice.repository.ReservationRepository;
import com.example.demo.reservationservice.service.ReservationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/reservations")
@RequiredArgsConstructor
public class    ReservationController {

    private final ReservationService reservationService;
    private final ReservationRepository reservationRepository;

    @PostMapping("/")
    public ResponseEntity<String> create(@RequestParam Long uId,
                                         @RequestParam String uName) {

        String key = reservationService.saveInitialData(uId, uName);
        return ResponseEntity.ok(key);

        // 프론트에서 ket가 null이면 실패하게 하기
    }

    // 좌석 데이터 받기
    @GetMapping("/search")
    public ResponseEntity<ReservationRequestDTO> search(@RequestParam String key) {
        ReservationRequestDTO dto = reservationService.getReservationData(key);
        return dto == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(dto);
    }

    // 좌석 선택
    @PostMapping("/seats")
    public ResponseEntity<ReservationRequestDTO> passport(@RequestBody List<SeatDTO> seats, @RequestParam String key) {
        ReservationRequestDTO dto = reservationService.updateSeats(key, seats);
        return dto == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(dto);
    }

    // 좌석 lock
    @PostMapping("/seats/lock")
    public ResponseEntity<?> selectSeats(@RequestBody List<SeatDTO> seats, @RequestParam String key) {
        Map<String, List<String>> result = reservationService.tryLockSeats(key, seats);
        return result == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(result);
    }

    /**
     * fId(항공편 ID)에 해당하는 모든 락된 좌석 조회
     * 예: GET /api/reservation/seats/locked/all?fId=123
     */
    @GetMapping("/seats/lock")
    public ResponseEntity<List<String>> getLockedByFlight(@RequestParam String key) {
        List<String> locked = reservationService.getLockedSeatsByFlightId(key);
        return ResponseEntity.ok(locked);
    }

    // 예매 확정 좌석 잠금
    @GetMapping("/seats/status")
    public ResponseEntity<List<String>> reservedSeats(@RequestParam Long fId) {
        return ResponseEntity.ok(reservationService.getReservedSpots(fId));
    }

    @PostMapping("/confirm")
    public ResponseEntity<String> confirmReservation(@RequestParam String key) {
        boolean success = reservationService.confirmReservation(key);
        return success
                ? ResponseEntity.ok("예약이 완료되었습니다.")
                : ResponseEntity.notFound().build();
    }

    @PostMapping("/cancel")
    public ResponseEntity<String> cancelReservation(@RequestParam String key) {
        boolean success = reservationService.cancelReservation(key);
        return success
                ? ResponseEntity.ok("예약을 취소했습니다.")
                : ResponseEntity.notFound().build();
    }


    @GetMapping("/search/payment/{uId}")
    public ResponseEntity<List<Reservation>> searchPayment(@PathVariable Long uId) {
        List<Reservation> reservation = reservationRepository.findByUId(uId);

        if (reservation.isEmpty()) {
            System.out.println("❌ 예약 없음");
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(reservation);
    }

    @DeleteMapping("delete/{rId}")
    public ResponseEntity<String> deleteReservation(@PathVariable Long rId) {
        Reservation reservation = reservationRepository.findById(rId)
                .orElseThrow(() -> new RuntimeException("해당 예약이 존재하지 않습니다."));

        if (reservation.getPayment() != null) {
            return ResponseEntity.badRequest().body("❌ 결제된 예약은 삭제할 수 없습니다.");
        }

        reservationRepository.deleteById(rId);
        return ResponseEntity.ok("✅ 예약이 삭제되었습니다.");
    }


}



