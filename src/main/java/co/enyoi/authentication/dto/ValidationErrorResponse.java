package co.enyoi.authentication.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ValidationErrorResponse(
        Instant timestamp,
        int status,
        String error,
        String message,
        String path,
        Map<String, List<String>> fieldErrors
) {
    public ValidationErrorResponse(int status, String error, String message, String path, Map<String, List<String>> fieldErrors) {
        this(Instant.now(), status, error, message, path, fieldErrors);
    }
}
