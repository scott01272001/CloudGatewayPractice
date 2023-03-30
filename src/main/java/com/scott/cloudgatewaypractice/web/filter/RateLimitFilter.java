package com.scott.cloudgatewaypractice.web.filter;

import com.github.benmanes.caffeine.cache.CacheLoader;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.google.common.util.concurrent.RateLimiter;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Log4j2
@Component
//@Order(1)
public class RateLimitFilter implements WebFilter {

    @Value("${server.auth-requests-per-second-per-client}")
    private double authRequestPerSecond;

    @Value("${server.requests-per-second-per-client}")
    private double requestPerSecondPerClient;

    private LoadingCache<String, RateLimiter> limiterCache;

    private final Set<String> authRequestPattern = Stream.of(".*basic.*").collect(Collectors.toSet());

    public RateLimitFilter() {
        log.info("Requests per second per client {}", requestPerSecondPerClient);
        limiterCache = Caffeine.newBuilder() //
                .initialCapacity(128) //
                .maximumSize(128) //
                .expireAfterAccess(1, TimeUnit.MINUTES) //
                .removalListener((k, v, cause) -> {
                    log.info("RateLimiter removed {}, {}", k, cause);
                }).build(new CacheLoader<>() {
                    @Override
                    public RateLimiter load(String key) throws Exception {
                        RateLimiter limiter = null;
                        if (authRequestPattern.stream().anyMatch(p -> key.matches(p))) {
                            limiter = RateLimiter.create(authRequestPerSecond);
                        } else {
                            limiter = RateLimiter.create(requestPerSecondPerClient);
                        }
                        log.info("New rateLimiter created for {}, {}", key, limiter);
                        return limiter;
                    }
                });
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        log.info("call rate limit!!!!!!!!!!!");

        ServerHttpRequest request = exchange.getRequest();
        String clientIp = clientIp(request);
        RateLimiter limiter = getRateLimiter(request);

        if (limiter != null && !limiter.tryAcquire(Duration.ofMillis(50))) {
            log.warn("Too many requests from {} on {}, {}", clientIp, request.getURI(), limiter);

            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
            response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
            return response.writeWith(Mono.just(response.bufferFactory().wrap("TOO_MANY_REQUESTS".getBytes())));
        }

        return chain.filter(exchange);
    }

    private RateLimiter getRateLimiter(ServerHttpRequest request) {
        String clientIp = clientIp(request);
        String uri = request.getURI().toString();

        log.info("clientIp: {}", clientIp);
        log.info("uri: {}", uri);

        if (authRequestPattern.stream().anyMatch(p -> uri.matches(p))) {
            clientIp = clientIp + uri;
            log.info("match auth pattern: {}", clientIp);
        }
        return limiterCache.get(clientIp);
    }

    private String clientIp(ServerHttpRequest request) {
        String ipAddress = request.getHeaders().getFirst("X-Forwarded-For");
        if (ipAddress == null) {
            ipAddress = request.getRemoteAddress().getHostName();
        }
        return ipAddress;
    }
}
