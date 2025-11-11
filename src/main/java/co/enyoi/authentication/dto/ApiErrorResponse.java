package co.enyoi.authentication.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiErrorResponse(
        String status,
        int statusCode,
        ErrorDetail error,
        String requestId
) {
    public ApiErrorResponse(int statusCode, ErrorDetail error, String requestId) {
        this("error", statusCode, error, requestId);
    }
}
