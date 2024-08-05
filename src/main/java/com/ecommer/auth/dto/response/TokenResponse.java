package com.ecommer.auth.dto.response;

public record TokenResponse(
        String accessToken,
        String tokenType,
        String refreshToken,
        Long expiresIn
) {

}
