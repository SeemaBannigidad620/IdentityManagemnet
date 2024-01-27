package com.aliens.ApiGateway.config;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ApiGatewayConfig {

    @Bean
    public RouteLocator routeLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                .route("IDENTITY-SERVICE", r -> r.path("/identity/**")
                        .uri("http://localhost:8080"))
                .route("USER-SERVICE", r -> r.path("/management/**")
                        .uri("http://localhost:8081"))
                // Add more routes as needed
                .build();
    }
}
