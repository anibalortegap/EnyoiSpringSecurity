package co.enyoi.authentication.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record AuthResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        Long expiresIn
) {
    public AuthResponse(String accessToken, String refreshToken) {
        this(accessToken, refreshToken, "Bearer", null);
    }

    public AuthResponse(String accessToken, String refreshToken, Long expiresIn) {
        this(accessToken, refreshToken, "Bearer", expiresIn);
    }
}
