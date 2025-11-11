package co.enyoi.authentication.dto;

public enum ErrorCode {
    // Authentication & Authorization Errors (1xxx)
    INVALID_CREDENTIALS("AUTH_1001", "Invalid username or password"),
    USER_NOT_FOUND("AUTH_1002", "User not found"),
    AUTHENTICATION_FAILED("AUTH_1003", "Authentication failed"),
    ACCESS_DENIED("AUTH_1004", "Access denied to the requested resource"),
    INSUFFICIENT_PERMISSIONS("AUTH_1005", "Insufficient permissions"),

    // JWT Token Errors (2xxx)
    INVALID_TOKEN("TOKEN_2001", "Invalid or malformed JWT token"),
    EXPIRED_TOKEN("TOKEN_2002", "JWT token has expired"),
    TOKEN_SIGNATURE_INVALID("TOKEN_2003", "JWT token signature validation failed"),
    MALFORMED_TOKEN("TOKEN_2004", "Malformed JWT token format"),

    // Refresh Token Errors (3xxx)
    REFRESH_TOKEN_NOT_FOUND("REFRESH_3001", "Refresh token not found"),
    REFRESH_TOKEN_EXPIRED("REFRESH_3002", "Refresh token has expired"),
    REFRESH_TOKEN_INVALID("REFRESH_3003", "Invalid refresh token"),

    // Validation Errors (4xxx)
    VALIDATION_FAILED("VALIDATION_4001", "Input validation failed"),
    INVALID_REQUEST_BODY("VALIDATION_4002", "Invalid request body format"),
    MISSING_REQUIRED_FIELD("VALIDATION_4003", "Required field is missing"),
    INVALID_FIELD_FORMAT("VALIDATION_4004", "Field format is invalid"),

    // Resource Errors (5xxx)
    RESOURCE_NOT_FOUND("RESOURCE_5001", "The requested resource was not found"),
    RESOURCE_ALREADY_EXISTS("RESOURCE_5002", "Resource already exists"),

    // Server Errors (9xxx)
    INTERNAL_SERVER_ERROR("SERVER_9001", "An unexpected internal server error occurred"),
    SERVICE_UNAVAILABLE("SERVER_9002", "Service temporarily unavailable"),
    BAD_REQUEST("SERVER_9003", "Bad request");

    private final String code;
    private final String message;

    ErrorCode(String code, String message) {
        this.code = code;
        this.message = message;
    }

    public String getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }
}
