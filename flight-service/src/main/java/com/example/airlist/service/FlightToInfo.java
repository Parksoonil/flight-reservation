package com.example.airlist.service;//package com.example.airlist.service;
//
//import com.example.airlist.entity.Flight;
//import com.example.airlist.entity.Flight_info;
//import com.example.airlist.repository.FlightInfoRepository;
//import com.example.airlist.repository.FlightRepository;
//import org.springframework.stereotype.Service;
//
//import java.time.LocalDateTime;
//import java.util.ArrayList;
//import java.util.List;
//import java.util.Map;
//import java.util.Random;
//
//@Service
//public class FlightToInfo {
//
//    private final FlightRepository flightRepository;
//    private final FlightInfoRepository flightInfoRepository;
//
//    public FlightToInfo(FlightInfoRepository flightInfoRepository , FlightRepository flightRepository){
//        this.flightInfoRepository = flightInfoRepository;
//        this.flightRepository =flightRepository;
//    }
//
//    // 항공기 종류 및 좌석수 매핑
//    private static final Map<String,Integer> AIRCRAFT_SEAT_MAP = Map.of(
//            "A320", 180,
//            "Boeing 777", 300,
//            "B737", 160,
//            "A380", 520,
//            "B787", 240
//    );
//    private String getRandomAircraftType(){
//        List<String> list = new ArrayList<>(AIRCRAFT_SEAT_MAP.keySet());
//        return list.get(new Random().nextInt(list.size()));
//    }
//
//    //무작위 항공기 종류 선택
//    private LocalDateTime getRandomFlightDateAfterJune2025() {
//        int randomDays = new Random().nextInt(180); //최대 6개월
//        return LocalDateTime.of(2025,6,1,0,0).plusDays(randomDays);
//    }
//
//    private String getRandomArrivalTime(String departureTime) {
//        try {
//            // 예: "1030" → 시: 10, 분: 30
//            int hour = Integer.parseInt(departureTime.substring(0, 2));
//            int minute = Integer.parseInt(departureTime.substring(2, 4));
//
//            // 랜덤 시간 (1~3시간)
//            int extraMinutes = (new Random().nextInt(120) + 60);
//
//            // LocalTime 사용
//            java.time.LocalTime dep = java.time.LocalTime.of(hour, minute);
//            java.time.LocalTime arr = dep.plusMinutes(extraMinutes);
//
//            return String.format("%02d%02d", arr.getHour(), arr.getMinute());
//        } catch (Exception e) {
//            return departureTime; // 실패 시 출발시간 반환
//        }
//    }
//
//
//    public void converAllFlightToFlightInfo() {
//        List<Flight> flights = flightRepository.findAll();
//
//        for(Flight f : flights){
//            if(flightInfoRepository.findByUfid(f.getUfid()).isPresent()) continue;
//
//
//            Flight_info info = new Flight_info();
//
//            if("I".equalsIgnoreCase(f.getIo())) {
//                info.setDeparture(f.getBoardingKor()); //출발지
//                info.setArrival(f.getArrivedKor()); //도착지
//            } else {
//                info.setDeparture(f.getAirport());
//                info.setArrival(f.getArrivedKor());
//            }
//
//            info.setDeparture(f.getAirport());
//            info.setArrival(f.getArrivedKor());
//            info.setDepartureTime(f.getStd());
//            info.setArrivalTime(getRandomArrivalTime(f.getStd()));
//
//            String aircraft = getRandomAircraftType();
//            info.setAircraftType(String.valueOf(AIRCRAFT_SEAT_MAP.get(aircraft)));
//            info.setSeatCount(AIRCRAFT_SEAT_MAP.get(aircraft));
//            info.setFlightClass("ECONOMY");
//
//            info.setFlightDate(getRandomFlightDateAfterJune2025());
//
//            flightInfoRepository.save(info);
//        }
//    }
//}
