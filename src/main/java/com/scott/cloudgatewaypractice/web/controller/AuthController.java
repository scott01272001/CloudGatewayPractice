package com.scott.cloudgatewaypractice.web.controller;

import com.scott.cloudgatewaypractice.dao.User;
import com.scott.cloudgatewaypractice.dao.repo.UserRepository;
import com.scott.cloudgatewaypractice.web.filter.JwtUtil;
import com.scott.cloudgatewaypractice.web.vo.JwtTokenResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;

@RestController
@Log4j2
@RequestMapping(value = "/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    @PostMapping(value = "/jwt")
    public JwtTokenResponse getJetToken(@RequestParam String username, @RequestParam String password) {
        User user = userRepository.findByEmail(username).orElseThrow(()->new UsernameNotFoundException("user not found"));
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new BadCredentialsException("password invalid");
        }
        String jwt = JwtUtil.generateToken(username, Duration.ofDays(1));
        return JwtTokenResponse.builder().accessToken(jwt).build();
    }

}
