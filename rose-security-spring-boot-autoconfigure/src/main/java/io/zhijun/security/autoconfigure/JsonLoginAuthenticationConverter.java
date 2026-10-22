package io.zhijun.security.autoconfigure;

import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.json.JsonMapper;

/** Converts the Starter's email/password JSON request into Spring Security authentication. */
public class JsonLoginAuthenticationConverter implements AuthenticationConverter {

    private final JsonMapper jsonMapper;

    public JsonLoginAuthenticationConverter(JsonMapper jsonMapper) {
        this.jsonMapper = jsonMapper;
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        try {
            LoginRequest body = jsonMapper.readValue(request.getInputStream(), LoginRequest.class);
            if (body == null
                    || body.email() == null
                    || body.email().isBlank()
                    || body.password() == null
                    || body.password().isEmpty()) {
                throw new BadCredentialsException("Authentication failed");
            }
            return UsernamePasswordAuthenticationToken.unauthenticated(
                    body.email().trim(), body.password());
        } catch (IOException exception) {
            throw new BadCredentialsException("Authentication failed", exception);
        } catch (JacksonException exception) {
            throw new BadCredentialsException("Authentication failed");
        }
    }

    private record LoginRequest(String email, String password) {}
}
