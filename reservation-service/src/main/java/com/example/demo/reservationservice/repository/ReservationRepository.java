package com.example.demo.reservationservice.repository;
import com.example.demo.reservationservice.dto.TicketDTO;
import com.example.demo.reservationservice.entitiy.Reservation;
import io.lettuce.core.dynamic.annotation.Param;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ReservationRepository extends JpaRepository<Reservation, Long> {
    @Query("SELECT r.sSpot FROM Reservation r WHERE r.fId = :fId")
    List<String> findReservationSSpotByFId(@Param("fId") Long fId);

    @Query("SELECT r FROM Reservation r WHERE r.rId = :rId")
    TicketDTO findReservationByRId(@Param("rId") Long rId);

    @Query("SELECT r FROM Reservation r WHERE r.rId = :rId")
    Optional<Reservation> findByRId(@Param("rId") Long rId);

    @Query("SELECT r FROM Reservation r WHERE r.uId = :uId")
    List<Reservation> findByUId(@Param("uId") Long uId);

    @Modifying
    @Transactional
    @Query("DELETE FROM Reservation r WHERE r.rId = :rId")
    void deleteByRId(@Param("rId") Long rId);
}
