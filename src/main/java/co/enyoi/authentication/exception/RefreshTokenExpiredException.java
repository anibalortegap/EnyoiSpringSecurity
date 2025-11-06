package co.enyoi.authentication.exception;

import java.time.Instant;

public class RefreshTokenExpiredException extends RuntimeException {

    private final Instant expiryDate;

    public RefreshTokenExpiredException(String token, Instant expiryDate) {
        super("Refresh token expired: " + token + " (expired at: " + expiryDate + ")");
        this.expiryDate = expiryDate;
    }

    public Instant getExpiryDate() {
        return expiryDate;
    }
}
