package com.scott.cloudgatewaypractice.web.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.server.ServerRequest;

@RestController
@RequestMapping(value = "/redirect")
@RequiredArgsConstructor
@Log4j2
public class RedirectController {

    @GetMapping()
    public void redirect() {

        log.info("this is redirect.");

    }

}
