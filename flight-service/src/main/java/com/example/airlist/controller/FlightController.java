package com.example.airlist.controller;

import com.example.airlist.dto.FlightInfoDto;
import com.example.airlist.entity.Flight_info;
import com.example.airlist.repository.FlightInfoRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;


@RestController
@RequestMapping("/api/flights")
public class FlightController {

    private final FlightInfoRepository flightInfoRepository;

    public FlightController(FlightInfoRepository flightInfoRepository) {
        this.flightInfoRepository = flightInfoRepository;
    }

    @GetMapping
    public ResponseEntity<List<FlightInfoDto>> getAllFlights() {
        List<Flight_info> entities = flightInfoRepository.findAll();

        List<FlightInfoDto> dtoList = entities.stream().map(e -> new FlightInfoDto(
                e.getId(),
                e.getDeparture().getANameKor(),
                e.getArrival().getANameKor(),
                e.getDepartureTime(),
                e.getArrivalTime(),
                e.getAircraft().getCModel(),
                e.getSeatCount(),
                e.getFlightClass()
        )).toList();

        return ResponseEntity.ok(dtoList);
    }



}

