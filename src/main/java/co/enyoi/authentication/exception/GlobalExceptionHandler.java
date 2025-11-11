package co.enyoi.authentication.exception;

import co.enyoi.authentication.dto.*;
import co.enyoi.authentication.util.RequestIdUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    // ========== Authentication & Authorization Exceptions ==========

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ApiErrorResponse> handleUserNotFoundException(
            UserNotFoundException ex,
            HttpServletRequest request) {

        String requestId = RequestIdUtil.getRequestId(request);
        logger.warn("[{}] User not found: {}", requestId, ex.getMessage());

        ErrorDetail errorDetail = new ErrorDetail(
                ErrorCode.USER_NOT_FOUND.getCode(),
                ErrorCode.USER_NOT_FOUND.getMessage(),
                ex.getMessage(),
                request.getRequestURI()
        );

        ApiErrorResponse response = new ApiErrorResponse(
                HttpStatus.NOT_FOUND.value(),
                errorDetail,
                requestId
        );

        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiErrorResponse> handleBadCredentials(
            BadCredentialsException ex,
            HttpServletRequest request) {

        String requestId = RequestIdUtil.getRequestId(request);
        logger.warn("[{}] Bad credentials attempt from: {}", requestId, request.getRemoteAddr());

        ErrorDetail errorDetail = new ErrorDetail(
                ErrorCode.INVALID_CREDENTIALS.getCode(),
                ErrorCode.INVALID_CREDENTIALS.getMessage(),
                request.getRequestURI()
        );

        ApiErrorResponse response = new ApiErrorResponse(
                HttpStatus.UNAUTHORIZED.value(),
                errorDetail,
                requestId
        );

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<ApiErrorResponse> handleUsernameNotFoundException(
            UsernameNotFoundException ex,
            HttpServletRequest request) {

        String requestId = RequestIdUtil.getRequestId(request);
        logger.warn("[{}] Username not found: {}", requestId, ex.getMessage());

        ErrorDetail errorDetail = new ErrorDetail(
                ErrorCode.INVALID_CREDENTIALS.getCode(),
                ErrorCode.INVALID_CREDENTIALS.getMessage(),
                request.getRequestURI()
        );

        ApiErrorResponse response = new ApiErrorResponse(
                HttpStatus.UNAUTHORIZED.value(),
                errorDetail,
                requestId
        );

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiErrorResponse> handleAuthenticationException(
            AuthenticationException ex,
            HttpServletRequest request) {

        String requestId = RequestIdUtil.getRequestId(request);
        logger.error("[{}] Authentication error: {}", requestId, ex.getMessage());

        ErrorDetail errorDetail = new ErrorDetail(
                ErrorCode.AUTHENTICATION_FAILED.getCode(),
                ErrorCode.AUTHENTICATION_FAILED.getMessage(),
                ex.getMessage(),
                request.getRequestURI()
        );

        ApiErrorResponse response = new ApiErrorResponse(
                HttpStatus.UNAUTHORIZED.value(),
                errorDetail,
                requestId
        );

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiErrorResponse> handleAccessDeniedException(
            AccessDeniedException ex,
            HttpServletRequest request) {

        String requestId = RequestIdUtil.getRequestId(request);
        logger.warn("[{}] Access denied to: {} from user: {}",
                requestId, request.getRequestURI(), request.getRemoteUser());

        ErrorDetail errorDetail = new ErrorDetail(
                ErrorCode.ACCESS_DENIED.getCode(),
                ErrorCode.ACCESS_DENIED.getMessage(),
                "You don't have permission to access this resource",
                request.getRequestURI()
        );

        ApiErrorResponse response = new ApiErrorResponse(
                HttpStatus.FORBIDDEN.value(),
                errorDetail,
                requestId
        );

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
    }

    // ========== JWT Exceptions ==========

    @ExceptionHandler(InvalidJwtTokenException.class)
    public ResponseEntity<ApiErrorResponse> handleInvalidJwtToken(
            InvalidJwtTokenException ex,
            HttpServletRequest request) {

        String requestId = RequestIdUtil.getRequestId(request);
        logger.warn("[{}] Invalid JWT token: {}", requestId, ex.getMessage());

        ErrorDetail errorDetail = new ErrorDetail(
                ErrorCode.INVALID_TOKEN.getCode(),
                ErrorCode.INVALID_TOKEN.getMessage(),
                ex.getMessage(),
                request.getRequestURI()
        );

        ApiErrorResponse response = new ApiErrorResponse(
                HttpStatus.UNAUTHORIZED.value(),
                errorDetail,
                requestId
        );

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    @ExceptionHandler(ExpiredJwtException.class)
    public ResponseEntity<ApiErrorResponse> handleExpiredJwtException(
            ExpiredJwtException ex,
            HttpServletRequest request) {

        String requestId = RequestIdUtil.getRequestId(request);
        logger.warn("[{}] Expired JWT token", requestId);

        ErrorDetail errorDetail = new ErrorDetail(
                ErrorCode.EXPIRED_TOKEN.getCode(),
                ErrorCode.EXPIRED_TOKEN.getMessage(),
                "Token expired at: " + ex.getClaims().getExpiration(),
                request.getRequestURI()
        );

        ApiErrorResponse response = new ApiErrorResponse(
                HttpStatus.UNAUTHORIZED.value(),
                errorDetail,
                requestId
        );

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    @ExceptionHandler(MalformedJwtException.class)
    public ResponseEntity<ApiErrorResponse> handleMalformedJwtException(
            MalformedJwtException ex,
            HttpServletRequest request) {

        String requestId = RequestIdUtil.getRequestId(request);
        logger.warn("[{}] Malformed JWT token: {}", requestId, ex.getMessage());

        ErrorDetail errorDetail = new ErrorDetail(
                ErrorCode.MALFORMED_TOKEN.getCode(),
                ErrorCode.MALFORMED_TOKEN.getMessage(),
                request.getRequestURI()
        );

        ApiErrorResponse response = new ApiErrorResponse(
                HttpStatus.BAD_REQUEST.value(),
                errorDetail,
                requestId
        );

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    @ExceptionHandler(SignatureException.class)
    public ResponseEntity<ApiErrorResponse> handleSignatureException(
            SignatureException ex,
            HttpServletRequest request) {

        String requestId = RequestIdUtil.getRequestId(request);
        logger.error("[{}] JWT signature validation failed: {}", requestId, ex.getMessage());

        ErrorDetail errorDetail = new ErrorDetail(
                ErrorCode.TOKEN_SIGNATURE_INVALID.getCode(),
                ErrorCode.TOKEN_SIGNATURE_INVALID.getMessage(),
                request.getRequestURI()
        );

        ApiErrorResponse response = new ApiErrorResponse(
                HttpStatus.UNAUTHORIZED.value(),
                errorDetail,
                requestId
        );

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    // ========== Refresh Token Exceptions ==========

    @ExceptionHandler(RefreshTokenNotFoundException.class)
    public ResponseEntity<ApiErrorResponse> handleRefreshTokenNotFound(
            RefreshTokenNotFoundException ex,
            HttpServletRequest request) {

        String requestId = RequestIdUtil.getRequestId(request);
        logger.warn("[{}] Refresh token not found: {}", requestId, ex.getMessage());

        ErrorDetail errorDetail = new ErrorDetail(
                ErrorCode.REFRESH_TOKEN_NOT_FOUND.getCode(),
                ErrorCode.REFRESH_TOKEN_NOT_FOUND.getMessage(),
                "The provided refresh token is invalid or does not exist",
                request.getRequestURI()
        );

        ApiErrorResponse response = new ApiErrorResponse(
                HttpStatus.NOT_FOUND.value(),
                errorDetail,
                requestId
        );

        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
    }

    @ExceptionHandler(RefreshTokenExpiredException.class)
    public ResponseEntity<ApiErrorResponse> handleRefreshTokenExpired(
            RefreshTokenExpiredException ex,
            HttpServletRequest request) {

        String requestId = RequestIdUtil.getRequestId(request);
        logger.warn("[{}] Refresh token expired: {}", requestId, ex.getMessage());

        ErrorDetail errorDetail = new ErrorDetail(
                ErrorCode.REFRESH_TOKEN_EXPIRED.getCode(),
                ErrorCode.REFRESH_TOKEN_EXPIRED.getMessage(),
                "Token expired at: " + ex.getExpiryDate() + ". Please login again",
                request.getRequestURI()
        );

        ApiErrorResponse response = new ApiErrorResponse(
                HttpStatus.UNAUTHORIZED.value(),
                errorDetail,
                requestId
        );

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    @ExceptionHandler(AuthenticationFailedException.class)
    public ResponseEntity<ApiErrorResponse> handleAuthenticationFailed(
            AuthenticationFailedException ex,
            HttpServletRequest request) {

        String requestId = RequestIdUtil.getRequestId(request);
        logger.error("[{}] Authentication failed: {}", requestId, ex.getMessage());

        ErrorDetail errorDetail = new ErrorDetail(
                ErrorCode.AUTHENTICATION_FAILED.getCode(),
                ErrorCode.AUTHENTICATION_FAILED.getMessage(),
                ex.getMessage(),
                request.getRequestURI()
        );

        ApiErrorResponse response = new ApiErrorResponse(
                HttpStatus.UNAUTHORIZED.value(),
                errorDetail,
                requestId
        );

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    // ========== Validation Exceptions ==========

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiValidationErrorResponse> handleValidationExceptions(
            MethodArgumentNotValidException ex,
            HttpServletRequest request) {

        String requestId = RequestIdUtil.getRequestId(request);
        logger.warn("[{}] Validation error on request: {}", requestId, request.getRequestURI());

        Map<String, List<String>> fieldErrors = new HashMap<>();

        ex.getBindingResult().getAllErrors().forEach(error -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();

            fieldErrors.computeIfAbsent(fieldName, k -> new ArrayList<>()).add(errorMessage);
        });

        ValidationErrorDetail errorDetail = new ValidationErrorDetail(
                ErrorCode.VALIDATION_FAILED.getCode(),
                ErrorCode.VALIDATION_FAILED.getMessage(),
                "One or more fields have validation errors",
                request.getRequestURI(),
                fieldErrors
        );

        ApiValidationErrorResponse response = new ApiValidationErrorResponse(
                HttpStatus.BAD_REQUEST.value(),
                errorDetail,
                requestId
        );

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    // ========== User Management Exceptions ==========

    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<ApiErrorResponse> handleUserAlreadyExists(
            UserAlreadyExistsException ex,
            HttpServletRequest request) {

        String requestId = RequestIdUtil.getRequestId(request);
        logger.warn("[{}] User already exists: {}", requestId, ex.getMessage());

        ErrorDetail errorDetail = new ErrorDetail(
                ErrorCode.RESOURCE_ALREADY_EXISTS.getCode(),
                ErrorCode.RESOURCE_ALREADY_EXISTS.getMessage(),
                ex.getMessage(),
                request.getRequestURI()
        );

        ApiErrorResponse response = new ApiErrorResponse(
                HttpStatus.CONFLICT.value(),
                errorDetail,
                requestId
        );

        return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
    }

    @ExceptionHandler(RoleNotFoundException.class)
    public ResponseEntity<ApiErrorResponse> handleRoleNotFound(
            RoleNotFoundException ex,
            HttpServletRequest request) {

        String requestId = RequestIdUtil.getRequestId(request);
        logger.warn("[{}] Role not found: {}", requestId, ex.getMessage());

        ErrorDetail errorDetail = new ErrorDetail(
                ErrorCode.RESOURCE_NOT_FOUND.getCode(),
                ErrorCode.RESOURCE_NOT_FOUND.getMessage(),
                ex.getMessage(),
                request.getRequestURI()
        );

        ApiErrorResponse response = new ApiErrorResponse(
                HttpStatus.NOT_FOUND.value(),
                errorDetail,
                requestId
        );

        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
    }

    // ========== Generic Exceptions ==========

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiErrorResponse> handleIllegalArgument(
            IllegalArgumentException ex,
            HttpServletRequest request) {

        String requestId = RequestIdUtil.getRequestId(request);
        logger.warn("[{}] Illegal argument: {}", requestId, ex.getMessage());

        ErrorDetail errorDetail = new ErrorDetail(
                ErrorCode.BAD_REQUEST.getCode(),
                ErrorCode.BAD_REQUEST.getMessage(),
                ex.getMessage(),
                request.getRequestURI()
        );

        ApiErrorResponse response = new ApiErrorResponse(
                HttpStatus.BAD_REQUEST.value(),
                errorDetail,
                requestId
        );

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiErrorResponse> handleGenericException(
            Exception ex,
            HttpServletRequest request) {

        String requestId = RequestIdUtil.getRequestId(request);
        logger.error("[{}] Unexpected error occurred", requestId, ex);

        ErrorDetail errorDetail = new ErrorDetail(
                ErrorCode.INTERNAL_SERVER_ERROR.getCode(),
                ErrorCode.INTERNAL_SERVER_ERROR.getMessage(),
                "An unexpected error occurred. Please try again later or contact support with request ID: " + requestId,
                request.getRequestURI()
        );

        ApiErrorResponse response = new ApiErrorResponse(
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                errorDetail,
                requestId
        );

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }
}
