package co.enyoi.authentication.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiValidationErrorResponse(
        String status,
        int statusCode,
        ValidationErrorDetail error,
        String requestId
) {
    public ApiValidationErrorResponse(int statusCode, ValidationErrorDetail error, String requestId) {
        this("error", statusCode, error, requestId);
    }
}
