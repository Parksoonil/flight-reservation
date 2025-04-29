package com.example.airlist.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class Webclient {
    @Bean
    public WebClient customWebClient() {
        return WebClient.builder().build();
    }
}
