package com.example.airlist.repository;

import com.example.airlist.entity.Flight;
import org.springframework.data.jpa.repository.JpaRepository;

public interface FlightRepository extends JpaRepository<Flight, String> {
}
