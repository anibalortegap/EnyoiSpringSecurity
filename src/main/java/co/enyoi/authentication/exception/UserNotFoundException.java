package co.enyoi.authentication.exception;

public class UserNotFoundException extends RuntimeException {

    public UserNotFoundException(String username) {
        super("User not found with username: " + username);
    }

    public UserNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
