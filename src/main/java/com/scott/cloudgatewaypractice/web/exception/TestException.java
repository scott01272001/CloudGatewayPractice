package com.scott.cloudgatewaypractice.web.exception;

public class TestException extends RuntimeException {

    public String error;
    public TestException(String error) {
        super();
        this.error = error;
    }

    public String getError() {
        return this.error;
    }

}
