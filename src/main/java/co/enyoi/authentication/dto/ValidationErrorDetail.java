package co.enyoi.authentication.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ValidationErrorDetail(
        String code,
        String message,
        String details,
        Instant timestamp,
        String path,
        Map<String, List<String>> fieldErrors
) {
    public ValidationErrorDetail(String code, String message, String path, Map<String, List<String>> fieldErrors) {
        this(code, message, null, Instant.now(), path, fieldErrors);
    }

    public ValidationErrorDetail(String code, String message, String details, String path, Map<String, List<String>> fieldErrors) {
        this(code, message, details, Instant.now(), path, fieldErrors);
    }
}
