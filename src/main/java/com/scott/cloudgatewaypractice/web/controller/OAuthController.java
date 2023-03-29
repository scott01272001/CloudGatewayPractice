package com.scott.cloudgatewaypractice.web.controller;

import com.scott.cloudgatewaypractice.dao.repo.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Log4j2
@RequestMapping(value = "/oauth")
@RequiredArgsConstructor
public class OAuthController {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;


}
