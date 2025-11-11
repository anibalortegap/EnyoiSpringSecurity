package co.enyoi.authentication.exception;

public class RoleNotFoundException extends RuntimeException {

    public RoleNotFoundException(String roleName) {
        super("Role not found: " + roleName);
    }

    public RoleNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
