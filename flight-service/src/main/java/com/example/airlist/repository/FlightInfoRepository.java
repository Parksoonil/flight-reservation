package com.example.airlist.repository;

import com.example.airlist.entity.Flight_info;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDate;

public interface FlightInfoRepository extends JpaRepository<Flight_info, Long> {

    @Query("SELECT f FROM Flight_info f " +
            "WHERE f.departure.aNameKor like %:departure% " +
            "AND f.arrival.aNameKor like %:arrival% " +
            "AND ( FUNCTION('DATE', f.departureTime) =:date)")
    Page<Flight_info> findByDepartureAndArrivalAndDate(@Param("departure") String departure,
                                                       @Param("arrival") String arrival,
                                                       @Param("date") LocalDate date,
    Pageable pageable);

    @EntityGraph(attributePaths = {"airCraft", "departure", "arrival"})
    @Query("SELECT f FROM Flight_info f " +
            "WHERE f.departure.aNameKor like %:departure% " +
            "AND f.arrival.aNameKor like %:arrival% " +
            "AND ( FUNCTION('DATE', f.departureTime) =:date)")
    Page<Flight_info> findWithAllJoins(@Param("departure") String departure,
                                       @Param("arrival") String arrival,
                                       @Param("date") LocalDate date,
                                       Pageable pageable);


    @Query("select f from Flight_info f where f.departure.aNameKor like %:departure% AND f.arrival.aNameKor like %:arrival%")
    Page<Flight_info> findByDepartureAAndArrival(@Param("departure") String departure, @Param("arrival")String arrival, Pageable pageable);


    @EntityGraph(attributePaths = {"departure", "arrival", "aircraft"})
    @Query("SELECT f FROM Flight_info f " +
            "WHERE f.departure.aNameKor like %:departure% " +
            "AND f.arrival.aNameKor like %:arrival% " +
            "AND FUNCTION('DATE', f.departureTime) = :date")
    Page<Flight_info> findWithDetails(@Param("departure") String departure,
                                      @Param("arrival") String arrival,
                                      @Param("date") LocalDate date,
                                      Pageable pageable);

    @EntityGraph(attributePaths = {"departure", "arrival", "aircraft"})
    @Query("SELECT f FROM Flight_info f " +
            "WHERE f.departure.aNameKor like %:departure% " +
            "AND f.arrival.aNameKor like %:arrival%")
    Page<Flight_info> findWithDetailsNoDate(@Param("departure") String departure,
                                            @Param("arrival") String arrival,
                                            Pageable pageable);


}
