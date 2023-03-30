package com.scott.cloudgatewaypractice.web.vo;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class JwtTokenResponse {

    @JsonProperty(value = "access_token")
    private String accessToken;

}
