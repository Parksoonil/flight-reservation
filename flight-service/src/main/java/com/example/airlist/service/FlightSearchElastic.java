package com.example.airlist.service;

import com.example.airlist.entity.FlightDocument;
import com.example.airlist.repository.FlightSearchRepositroy;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
public class FlightSearchElastic {

    private final FlightSearchRepositroy flightSearchRepositroy;

    public FlightSearchElastic(FlightSearchRepositroy flightSearchRepositroy) {
        this.flightSearchRepositroy = flightSearchRepositroy;
    }

    public Page<FlightDocument> searchElastic(String departure, String arrival, LocalDateTime date, int page, int size) {
        Pageable pageable = PageRequest.of(page, size);


        if (date == null) {
            // departureTime 없이 검색 (전체 중 출도착지만 매칭)
            return flightSearchRepositroy.findByDepartureNameContainingAndArrivalNameContaining(departure, arrival, pageable) ;  } else {
            return flightSearchRepositroy.findByDepartureNameContainingAndArrivalNameContainingAndDepartureTimeAfter(departure, arrival, date, pageable);
        }
    }

    public Page<FlightDocument> findAllPaged(Pageable pageable){
        return flightSearchRepositroy.findAll(
                PageRequest.of(pageable.getPageNumber(), pageable.getPageSize(), Sort.by("departureTime").ascending())
        );
    }

}