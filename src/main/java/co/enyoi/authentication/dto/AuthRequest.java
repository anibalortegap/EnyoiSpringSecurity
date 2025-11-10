package co.enyoi.authentication.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record AuthRequest(
        @NotBlank(message = "Username is required")
        @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
        @Pattern(regexp = "^[a-zA-Z0-9._-]+$",
                message = "Username can only contain letters, numbers, dots, underscores and hyphens")
        String username,

        @NotBlank(message = "Password is required")
        @Size(min = 6, max = 100, message = "Password must be between 6 and 100 characters")
        String password
) {
}
