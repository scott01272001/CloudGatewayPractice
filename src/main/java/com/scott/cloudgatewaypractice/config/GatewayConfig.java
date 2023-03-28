package com.scott.cloudgatewaypractice.config;

import com.scott.cloudgatewaypractice.web.controller.web.filter.TestFilter;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GatewayConfig {

    @Bean
    public GlobalFilter addTestFilter() {
        return new TestFilter();
    }

}
