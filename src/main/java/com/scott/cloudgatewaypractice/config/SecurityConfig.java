package com.scott.cloudgatewaypractice.config;

import com.scott.cloudgatewaypractice.dao.repo.UserRepository;
import com.scott.cloudgatewaypractice.web.filter.JwtSecurityFilter;
import com.scott.cloudgatewaypractice.web.filter.RateLimitFilter;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Optional;

@EnableWebFluxSecurity
@RequiredArgsConstructor
@Log4j2
@Configuration
public class SecurityConfig {

//    @Bean
//    public JwtSecurityFilter jwtSecurityFilter() {
//        return new JwtSecurityFilter();
//    }
    private final UserRepository userRepository;

   // private final JwtSecurityFilter jwtSecurityFilter;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http = http.cors().and().csrf().disable();
        http = http.securityContextRepository(NoOpServerSecurityContextRepository.getInstance());

        http.exceptionHandling().authenticationEntryPoint((exchange, ex) -> {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            Flux body = Flux.just(exchange.getResponse().bufferFactory().wrap(ex.getMessage().getBytes()));
            return exchange.getResponse().writeWith(body);
        });

        http = http.authorizeExchange().pathMatchers("/auth/**").permitAll().and();

        http = http.authorizeExchange().pathMatchers("/api/**").authenticated().and().httpBasic().and();

        http = http.authorizeExchange().pathMatchers("/redirect/**").permitAll().and();

        http = http.authenticationManager(authenticationManager(passwordEncoder()));

//        http.addFilterBefore(new RateLimitFilter(), SecurityWebFiltersOrder.HTTP_BASIC);
      //  http.addFilterBefore(jwtSecurityFilter, SecurityWebFiltersOrder.HTTP_BASIC);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public ReactiveAuthenticationManager authenticationManager(PasswordEncoder passwordEncoder) {
        return new ReactiveAuthenticationManager() {
            @Override
            public Mono<Authentication> authenticate(Authentication authentication) throws AuthenticationException {

                log.info("basic auth user name: {}", authentication.getName());

                Optional<com.scott.cloudgatewaypractice.dao.User> user = userRepository.findByEmail(authentication.getName());

                if (!user.isPresent()) {
                    return Mono.error(new UsernameNotFoundException("User not found"));
                }

                UserDetails userDetails = User.withDefaultPasswordEncoder()
                        .username(user.get().getEmail())
                        .password(user.get().getPassword()).passwordEncoder(p -> passwordEncoder().encode(p))
                        .roles("USER")
                        .build();

                if (passwordEncoder.matches(authentication.getCredentials().toString(), userDetails.getPassword())) {
                    return Mono.just(new UsernamePasswordAuthenticationToken(userDetails, authentication.getCredentials(), userDetails.getAuthorities()));
                }
                return Mono.empty();
            }
        };
    }

}
