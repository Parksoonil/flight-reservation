package com.example.demo.flightreservationgateway.filter;

import com.example.demo.flightreservationgateway.util.TokenProvider;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
@Order(0)
public class JwtAuthenticationFilter implements GlobalFilter {

    private final TokenProvider tokenProvider;

    public JwtAuthenticationFilter(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        System.out.println("chain filter 접근");
        String path = exchange.getRequest().getPath().toString();
        System.out.println("path : " + path);
        List<String> whitelist = List.of("/api/users/login", "/api/users/signup", "/api/users/refresh", "/api/flight/**", "/api/autocomplete/**");
        if (whitelist.contains(path)) {
            return chain.filter(exchange);
        }
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        System.out.println("authHeader : " + authHeader);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return unauthorized(exchange);
        }

        String token = authHeader.substring(7);
        if (!tokenProvider.validateToken(token)) {
            return unauthorized(exchange);
        }

        String email = tokenProvider.getEmailFromToken(token);
        ServerHttpRequest newRequest = exchange.getRequest().mutate()
                .header("X-User-Email", email)
                .build();
        System.out.println("newRequest : " + newRequest);
        System.out.println("newRequest.header : " + newRequest.getHeaders());
        System.out.println(exchange.mutate().request(newRequest).build());
        return chain.filter(exchange.mutate().request(newRequest).build());
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }
}
