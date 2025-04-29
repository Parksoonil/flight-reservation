package com.example.airlist.config;//package com.example.airlist.config;
//
//import com.example.airlist.dto.FlightJsonDto;
//import com.example.airlist.dto.FlightsResponse;
//import com.example.airlist.entity.Flight;
//import com.example.airlist.repository.FlightRepository;
//import com.fasterxml.jackson.databind.ObjectMapper;
//import org.springframework.boot.CommandLineRunner;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//
//import java.io.InputStream;
//import java.util.List;
//
//@Configuration
//public class DataLoader {
//
//    @Bean
//    public CommandLineRunner loadFlightData(FlightRepository flightRepository) {
//        return args -> {
//            ObjectMapper mapper = new ObjectMapper();
//            InputStream input = getClass().getResourceAsStream("/static/response.json");
//
//            // ✅ JSON 전체 구조를 FlightsResponse로 파싱
//            FlightsResponse response = mapper.readValue(input, FlightsResponse.class);
//            List<FlightJsonDto> dtos = response.getData();
//
//            List<Flight> flights = dtos.stream()
//                    .map(dto -> Flight.builder()
//                            .ufid(dto.getUfid())
//                            .airlineKorean(dto.getAirlineKorean())
//                            .airlineEnglish(dto.getAirlineEnglish())
//                            .airport(dto.getAirport())
//                            .airFln(dto.getAirFln())
//                            .arrivedKor(dto.getArrivedKor())
//                            .boardingKor(dto.getBoardingKor())
//                            .city(dto.getCity())
//                            .etd(dto.getEtd())
//                            .flightDate(dto.getFlightDate())
//                            .line(dto.getLine())
//                            .rmkKor(dto.getRmkKor())
//                            .std(dto.getStd())
//                            .io(dto.getIo())
//                            .build())
//                    .toList();
//
//            flightRepository.saveAll(flights);
//            System.out.println("✅ 총 " + flights.size() + "건 저장 완료!");
//        };
//    }
//}
