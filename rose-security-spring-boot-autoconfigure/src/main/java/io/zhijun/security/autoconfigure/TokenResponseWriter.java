package io.zhijun.security.autoconfigure;

import io.zhijun.security.core.IssuedSessionTokens;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Clock;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import tools.jackson.databind.json.JsonMapper;

/** Shared token response serialization for login and refresh success handlers. */
final class TokenResponseWriter {

    private TokenResponseWriter() {}

    static void write(HttpServletResponse response, IssuedSessionTokens tokens, JsonMapper jsonMapper, Clock clock)
            throws IOException {
        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
        long expiresIn = Math.max(
                0,
                tokens.accessTokenExpiresAt().getEpochSecond() - clock.instant().getEpochSecond());
        jsonMapper.writeValue(
                response.getOutputStream(),
                new AuthenticationTokenResponse(
                        tokens.accessToken(),
                        "Bearer",
                        expiresIn,
                        tokens.refreshToken(),
                        tokens.refreshTokenExpiresAt(),
                        tokens.sessionId()));
        response.flushBuffer();
    }
}
