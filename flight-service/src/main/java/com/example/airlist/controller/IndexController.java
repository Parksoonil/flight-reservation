package com.example.airlist.controller;

import com.example.airlist.service.FlightElasticIndexer;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class IndexController {
    private final FlightElasticIndexer indexer;

    @GetMapping("/api/index")
    public String indexData() {
        indexer.indexAll();
        return "인덱싱 완료!";
    }
}
