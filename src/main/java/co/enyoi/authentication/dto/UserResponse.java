package co.enyoi.authentication.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.Instant;
import java.util.Set;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record UserResponse(
        Long id,
        String username,
        Set<String> roles,
        Instant createdAt
) {
    public UserResponse(Long id, String username, Set<String> roles) {
        this(id, username, roles, Instant.now());
    }
}
