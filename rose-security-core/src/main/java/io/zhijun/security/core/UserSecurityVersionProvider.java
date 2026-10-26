package io.zhijun.security.core;

/** Reads a user's current security version without introducing another user-state model. */
public interface UserSecurityVersionProvider {

    long currentVersion(String username);
}
