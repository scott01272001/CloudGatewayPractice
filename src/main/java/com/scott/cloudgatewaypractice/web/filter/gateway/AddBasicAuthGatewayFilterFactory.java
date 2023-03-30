package com.scott.cloudgatewaypractice.web.filter.gateway;

import com.google.common.collect.Lists;
import com.google.common.net.HttpHeaders;
import lombok.Data;
import lombok.extern.log4j.Log4j2;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.cloud.gateway.filter.factory.RewritePathGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.springframework.cloud.gateway.support.GatewayToStringStyler.filterToStringCreator;

@Log4j2
@Component
public class AddBasicAuthGatewayFilterFactory
        extends AbstractGatewayFilterFactory<AddBasicAuthGatewayFilterFactory.Config> {

    public AddBasicAuthGatewayFilterFactory() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        String basicAuthToken = generateBasicAuthToken(config.username, config.password);
        return new GatewayFilter() {
            @Override
            public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

                log.info("call add basic filter");

                ServerHttpRequest request = exchange.getRequest().mutate()
                        .headers(httpHeaders -> httpHeaders.put(HttpHeaders.AUTHORIZATION, Lists.newArrayList(basicAuthToken))).build();
                return chain.filter(exchange.mutate().request(request).build());
            }

            @Override
            public String toString() {
                return filterToStringCreator(AddBasicAuthGatewayFilterFactory.this)
                        .append("username", config.username).toString();
            }

        };
    }

    private String generateBasicAuthToken(String username, String password) {
        String authString = username + ":" + password;
        byte[] authBytes = authString.getBytes(StandardCharsets.UTF_8);
        String encodedAuth = Base64.getEncoder().encodeToString(authBytes);
        String basicToken = "Basic " + encodedAuth;
        return basicToken;
    }

    @Data
    public static class Config {
        private String username;
        private String password;
    }

}
