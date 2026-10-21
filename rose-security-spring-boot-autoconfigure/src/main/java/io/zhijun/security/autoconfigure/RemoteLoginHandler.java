package io.zhijun.security.autoconfigure;

import io.zhijun.security.core.UserSessionClientInfo;

/** Application-owned location detection and notification after a login token response is written. */
@FunctionalInterface
public interface RemoteLoginHandler {

    /**
     * Detects and notifies about a remote login using application-owned location history and delivery services.
     * Implementations must not retain credentials or attempt to access token values.
     */
    void handle(String username, UserSessionClientInfo clientInfo, String sessionId);
}
