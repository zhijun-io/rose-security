package io.zhijun.security.autoconfigure;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.Instant;

/** JSON response returned by the Starter's login and refresh filters. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record AuthenticationTokenResponse(
        String access_token,
        String token_type,
        long expires_in,
        String refresh_token,
        Instant refresh_expires_at,
        String session_id) {

    @Override
    public String toString() {
        return "AuthenticationTokenResponse[access_token=<redacted>, token_type=" + token_type
                + ", expires_in=" + expires_in
                + ", refresh_token=<redacted>, refresh_expires_at=" + refresh_expires_at
                + ", session_id=" + session_id + "]";
    }
}
