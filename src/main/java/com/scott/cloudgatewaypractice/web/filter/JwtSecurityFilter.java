package com.scott.cloudgatewaypractice.web.filter;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.ServerHttpBasicAuthenticationConverter;
import org.springframework.security.web.server.authentication.WebFilterChainServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.List;

@Log4j2
//@Component
//@Order(2)
public class JwtSecurityFilter implements WebFilter {

    private static final String TOKEN_PREFIX = "Bearer ";

    private ServerSecurityContextRepository securityContextRepository = NoOpServerSecurityContextRepository
            .getInstance();
    private ServerAuthenticationSuccessHandler authenticationSuccessHandler = new WebFilterChainServerAuthenticationSuccessHandler();

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String header = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        log.info("AUTHORIZATION header: {}", header);

        if (StringUtils.hasText(header) && header.startsWith(TOKEN_PREFIX)) {
            try {
                Authentication authentication = getAuthentication(header.substring(TOKEN_PREFIX.length()));
                SecurityContextImpl securityContext = new SecurityContextImpl();
                securityContext.setAuthentication(authentication);

                return securityContextRepository.save(exchange, securityContext)
                        .then(authenticationSuccessHandler.onAuthenticationSuccess(new WebFilterExchange(exchange, chain), authentication))
                        .subscriberContext(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext)));

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

                System.out.println("GrantedAuthority: " + authorities);

                return new PreAuthenticatedAuthenticationToken(user, null, authorities);
            }
        }
        return null;
    }

}
