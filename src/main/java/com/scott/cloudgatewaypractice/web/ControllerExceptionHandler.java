package com.scott.cloudgatewaypractice.web;

import com.scott.cloudgatewaypractice.web.exception.TestException;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.handler.ResponseStatusExceptionHandler;

@Log4j2
@RestControllerAdvice
public class ControllerExceptionHandler {

    @ExceptionHandler(TestException.class)
    public ResponseEntity<String> handleError(TestException ex, ServerWebExchange exchange) {
        return new ResponseEntity<>(ex.getError(), HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
