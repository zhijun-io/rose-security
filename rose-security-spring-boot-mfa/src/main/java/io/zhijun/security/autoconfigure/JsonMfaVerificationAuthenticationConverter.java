package io.zhijun.security.autoconfigure;

import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.json.JsonMapper;

/** Reads an opaque pending-login token and one factor proof from JSON. */
public class JsonMfaVerificationAuthenticationConverter implements AuthenticationConverter {

    private final JsonMapper jsonMapper;

    public JsonMfaVerificationAuthenticationConverter(JsonMapper jsonMapper) {
        this.jsonMapper = jsonMapper;
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        try {
            VerificationRequest body = jsonMapper.readValue(request.getInputStream(), VerificationRequest.class);
            if (body == null || blank(body.transaction_token()) || blank(body.method()) || blank(body.proof())) {
                throw new BadCredentialsException("Authentication failed");
            }
            return MfaVerificationAuthenticationToken.unauthenticated(
                    body.transaction_token(), body.method(), body.proof());
        } catch (IOException | JacksonException exception) {
            throw new BadCredentialsException("Authentication failed", exception);
        }
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }

    private record VerificationRequest(String transaction_token, String method, String proof) {}
}
