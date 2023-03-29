package com.scott.cloudgatewaypractice.web.filter;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.List;

@Configuration
@Log4j2
@RequiredArgsConstructor
public class JwtSecurityFilter implements WebFilter {

    private static final String TOKEN_PREFIX = "Bearer ";

    private final ObjectMapper objectMapper;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        log.info("call JwtSecurityFilter!!!!!!!!!!!");

        String header = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        log.info("AUTHORIZATION header: {}", header);

        if (StringUtils.hasText(header) && header.startsWith(TOKEN_PREFIX)) {
            try {
                Authentication authentication = getAuthentication(header.substring(TOKEN_PREFIX.length()));
                ReactiveSecurityContextHolder.getContext().doOnSuccess(c->c.setAuthentication(authentication)).block();
            } catch (JWTVerificationException e) {
                ServerHttpResponse response = exchange.getResponse();
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
                return response.writeWith(Mono.just(response.bufferFactory().wrap("token not valid".getBytes())));
            }
        }

        return chain.filter(exchange);
    }

    private Authentication getAuthentication(String token) {
        if (token != null) {
            // parse the token.
            DecodedJWT jwt = JwtUtil.decodeToken(token);
            String user;
            if (jwt != null && (user = jwt.getSubject()) != null) {
                List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList(jwt.getClaim("scope").asArray(String.class));
                return new PreAuthenticatedAuthenticationToken(user, null, authorities);
            }
        }
        return null;
    }

}
