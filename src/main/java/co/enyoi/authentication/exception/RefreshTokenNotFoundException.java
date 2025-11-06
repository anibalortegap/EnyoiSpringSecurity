package co.enyoi.authentication.exception;

public class RefreshTokenNotFoundException extends RuntimeException {

    public RefreshTokenNotFoundException(String token) {
        super("Refresh token not found: " + token);
    }

    public RefreshTokenNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
