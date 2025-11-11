package co.enyoi.authentication.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiSuccessResponse<T>(
        String status,
        int statusCode,
        T data,
        String requestId
) {
    public ApiSuccessResponse(int statusCode, T data, String requestId) {
        this("success", statusCode, data, requestId);
    }

    public ApiSuccessResponse(T data, String requestId) {
        this("success", 200, data, requestId);
    }
}
