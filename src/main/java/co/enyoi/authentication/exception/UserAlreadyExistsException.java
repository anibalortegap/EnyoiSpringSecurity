package co.enyoi.authentication.exception;

public class UserAlreadyExistsException extends RuntimeException {

    public UserAlreadyExistsException(String username) {
        super("User already exists with username: " + username);
    }

    public UserAlreadyExistsException(String message, Throwable cause) {
        super(message, cause);
    }
}
