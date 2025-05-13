package com.example.demo.reservationservice.service;

import com.example.demo.reservationservice.dto.*;
import com.example.demo.reservationservice.entitiy.Reservation;
import com.example.demo.reservationservice.repository.ReservationRepository;
import com.example.demo.reservationservice.util.TimedStorage;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Transactional
@Service
@RequiredArgsConstructor
public class ReservationService {

    private final ObjectMapper objectMapper;
    private final ReservationRepository reservationRepository;
    private final KafkaTemplate<String, String> kafkaTemplate;
    private final TimedStorage timedStorage;

    private FlightDto flightDto;
    private final Object lock = new Object();

    public void save(FlightDto dto) {
        synchronized (lock) {
            this.flightDto = dto;
            lock.notifyAll(); // 대기 중인 스레드에 알림
        }
    }

    public FlightDto getLatestFlight() {
        synchronized (lock) {
            if (flightDto == null) {
                try {
                    lock.wait(5000); // 지정된 시간 동안 대기
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            return flightDto;
        }
    }

    public String saveInitialData(Long uId, String uName) {

        FlightDto flightDto = getLatestFlight();

        if (flightDto == null) {
            System.out.println("⚠️ flightDto가 Kafka 메시지로부터 아직 초기화되지 않았습니다.");

            flightDto = FlightDto.builder()
                    .id(999L)
                    .departureName("서울")
                    .arrivalName("부산")
                    .departureTime(LocalDateTime.now().plusDays(1).withHour(10).withMinute(0))
                    .arrivalTime(LocalDateTime.now().plusDays(1).withHour(11).withMinute(10))
                    .seatCount(20)
                    .aircraftType("Boeing-737")
                    .build();
        }

        String key = UUID.randomUUID().toString();
        ReservationRequestDTO dto = new ReservationRequestDTO();

        ReservationDTO reservationDTO = ReservationDTO.builder()
                .fId(flightDto.getId())
                .fDeparture(flightDto.getDepartureName())
                .fArrival(flightDto.getArrivalName())
                .fDepartureTime(flightDto.getDepartureTime())
                .fArrivalTime(flightDto.getArrivalTime())
                .fSeatCount(flightDto.getSeatCount())
                .fAircraftType(flightDto.getAircraftType())
                .uId(uId)
                .uName(uName)
                .build();

        dto.setReservation(reservationDTO);
        timedStorage.put(key, dto);

        return key;
    }




    public ReservationRequestDTO getReservationData(String key) {
        return objectMapper.convertValue(timedStorage.get(key), ReservationRequestDTO.class);
    }

    public ReservationRequestDTO updateSeats(String key, List<SeatDTO> seats) {
        ReservationRequestDTO request = getReservationData(key);
        if (request != null) {
            request.setSeats(new ArrayList<>(seats));
            timedStorage.put(key, request);
        }
        return request;
    }

    public Map<String, List<String>> tryLockSeats(String key, List<SeatDTO> seats) {
        ReservationRequestDTO request = getReservationData(key);
        if (request == null) return null;

        Long fId = request.getReservation().getFId();
        List<String> locked = new ArrayList<>();
        List<String> failed = new ArrayList<>();

        for (SeatDTO seat : seats) {
            if (timedStorage.tryLockSeat(fId, seat.getSSpot())) {
                locked.add(seat.getSSpot());
            } else {
                failed.add(seat.getSSpot());
            }
        }

        List<SeatDTO> successSeats = seats.stream()
                .filter(seat -> locked.contains(seat.getSSpot()))
                .toList();
        request.setSeats(successSeats);
        timedStorage.put(key, request);

        return Map.of("locked", locked, "failed", failed);
    }

    /**
     * 특정 항공편(flightId)에 대해 현재 락 중인 좌석 목록을 반환합니다.
     */
    public List<String> getLockedSeatsByFlightId(String key) {
        ReservationRequestDTO request = getReservationData(key);
        Long fId = request.getReservation().getFId();
        return timedStorage.getLockedSpotsByFlight(fId);
    }

    public List<String> getReservedSpots(Long fId) {
        return reservationRepository.findReservationSSpotByFId(fId);
    }

    public boolean confirmReservation(String key) {
        ReservationRequestDTO request = getReservationData(key);
        if (request == null) return false;

        ReservationDTO dto = request.getReservation();
        List<SeatDTO> seats = request.getSeats();
        List<Reservation> reservations = new ArrayList<>();

        String groupId = UUID.randomUUID().toString();



        for (SeatDTO seat : seats) {
            reservations.add(Reservation.builder()
                    .uId(dto.getUId())
                    .fId(dto.getFId())
                    .rDate(LocalDateTime.now())
                    .fDeparture(dto.getFDeparture())
                    .fArrival(dto.getFArrival())
                    .fDepartureTime(dto.getFDepartureTime())
                    .fArrivalTime(dto.getFArrivalTime())
                    .ticketPrice(seat.getSPrice())
                    .fAircraftType(dto.getFAircraftType())
                    .groupId(groupId)
                    .cId(dto.getCId())
                    .uName(dto.getUName())
                    .sName(seat.getSName())
                    .sSpot(seat.getSSpot())
                    .sClass(seat.getSClass())
                    .build());
        }

        reservationRepository.saveAll(reservations);
        timedStorage.remove(key);

        return true;
    }

    public boolean cancelReservation(String key) {

        ReservationRequestDTO request = getReservationData(key);
        if (request == null) {return false;}

        timedStorage.remove(key);
        Long fId = request.getReservation().getFId();
        // 분리된 메서드 호출
        releaseSeatLocks(fId, request.getSeats());

        return true;
    }

    // 좌석 잠금 해제를 처리하는 분리된 메서드
    private void releaseSeatLocks(Long fId, List<SeatDTO> seats) {
        for (SeatDTO seat : seats) {
            String seatNo = seat.getSSpot();
            timedStorage.releaseSeatLock(fId, seatNo);
        }
    }


}
