package io.zhijun.security.autoconfigure;

import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import tools.jackson.core.JacksonException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import tools.jackson.databind.json.JsonMapper;

/** Converts the Starter's refresh-token JSON request into its Spring Security authentication token. */
public class JsonRefreshTokenAuthenticationConverter implements AuthenticationConverter {

    private final JsonMapper jsonMapper;

    public JsonRefreshTokenAuthenticationConverter(JsonMapper jsonMapper) {
        this.jsonMapper = jsonMapper;
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        try {
            RefreshRequest body = jsonMapper.readValue(request.getInputStream(), RefreshRequest.class);
            if (body == null
                    || body.refresh_token() == null
                    || body.refresh_token().isBlank()) {
                throw new BadCredentialsException("Authentication failed");
            }
            return RefreshRequestAuthenticationToken.unauthenticated(body.refresh_token());
        } catch (IOException exception) {
            throw new BadCredentialsException("Authentication failed", exception);
        } catch (JacksonException exception) {
            throw new BadCredentialsException("Authentication failed");
        }
    }

    private record RefreshRequest(String refresh_token) {}
}
