package dev.authstarter.security.core;

/** Reads account availability and security version from the integrating application's user model. */
public interface UserSecurityStateProvider {

    UserSecurityState findState(String userId);
}
