package com.example.airlist.controller;

import com.example.airlist.dto.FlightDto;
import com.example.airlist.service.FlightKafkaProducer;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/kafka")
@RequiredArgsConstructor
public class KafkaTestController {

    private final FlightKafkaProducer flightKafkaProducer;

    @PostMapping("/publish")
    public ResponseEntity<String> publishFlight(@RequestBody FlightDto flightDto){
        flightKafkaProducer.sendFlightData(flightDto);
        return ResponseEntity.ok("전송완료");
    }
}
