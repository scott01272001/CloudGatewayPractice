package com.scott.cloudgatewaypractice.web.controller;

import com.scott.cloudgatewaypractice.web.exception.TestException;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/basic")
@RequiredArgsConstructor
@Log4j2
public class BasicAuthController {

    @GetMapping
    public String login() {
        throw new TestException("basic exception");
//        return "sucess";
    }

}
