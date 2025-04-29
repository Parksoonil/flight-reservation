package com.example.airlist.service;

import com.example.airlist.dto.FlightDto;
import lombok.RequiredArgsConstructor;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class FlightKafkaProducer {

    private final KafkaTemplate<String, FlightDto> kafkaTemplate;
    private final String topicName = "flight-topic";

    public void sendFlightData(FlightDto flightDto){
        kafkaTemplate.send(topicName, flightDto);
        System.out.println("항공편 전송완료" + flightDto.getId());
    }
}
