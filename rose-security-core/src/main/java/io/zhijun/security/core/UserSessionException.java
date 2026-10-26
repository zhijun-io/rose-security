package io.zhijun.security.core;

/** Safe-to-classify authentication failure; API responses should use generic public messages. */
public class UserSessionException extends RuntimeException {

    private final Reason reason;

    public UserSessionException(Reason reason) {
        super("Token session operation failed");
        this.reason = reason;
    }

    public Reason reason() {
        return reason;
    }

    public enum Reason {
        INVALID_REFRESH_TOKEN,
        REFRESH_TOKEN_REPLAYED,
        SESSION_INVALIDATED,
        SESSION_LIMIT_REACHED,
        USER_UNAVAILABLE
    }
}
