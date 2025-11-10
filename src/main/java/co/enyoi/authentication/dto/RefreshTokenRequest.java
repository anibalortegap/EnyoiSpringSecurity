package co.enyoi.authentication.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record RefreshTokenRequest(
        @NotBlank(message = "Refresh token is required")
        @Pattern(regexp = "^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$",
                message = "Invalid refresh token format")
        String refreshToken
) {
}
