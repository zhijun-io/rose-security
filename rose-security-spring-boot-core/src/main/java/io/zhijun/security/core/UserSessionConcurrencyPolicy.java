package io.zhijun.security.core;

/** Selects the active-session limit and behavior for a user when a new session is created. */
@FunctionalInterface
public interface UserSessionConcurrencyPolicy {

    Policy forUser(String username);

    record Policy(int maximumActiveSessions, LimitBehavior limitBehavior) {

        public Policy {
            if (maximumActiveSessions < 0) {
                throw new IllegalArgumentException("maximumActiveSessions must not be negative");
            }
            if (limitBehavior == null) {
                throw new IllegalArgumentException("limitBehavior must not be null");
            }
        }

        public static Policy unlimited() {
            return new Policy(0, LimitBehavior.DENY_NEW);
        }
    }

    enum LimitBehavior {
        DENY_NEW,
        REVOKE_OLDEST
    }
}
