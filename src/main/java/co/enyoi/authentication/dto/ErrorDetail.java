package co.enyoi.authentication.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.Instant;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ErrorDetail(
        String code,
        String message,
        String details,
        Instant timestamp,
        String path
) {
    public ErrorDetail(String code, String message, String path) {
        this(code, message, null, Instant.now(), path);
    }

    public ErrorDetail(String code, String message, String details, String path) {
        this(code, message, details, Instant.now(), path);
    }
}
