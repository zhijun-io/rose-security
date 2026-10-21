package io.zhijun.security.autoconfigure;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

/** Writes the response for the default token-session logout handler. */
public class UserSessionLogoutSuccessHandler implements LogoutSuccessHandler {

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException {
        Object failure = request.getAttribute(UserSessionLogoutHandler.FAILURE_ATTRIBUTE);
        if (failure instanceof HttpStatus status) {
            if (status == HttpStatus.UNAUTHORIZED) {
                response.setHeader("WWW-Authenticate", "Bearer error=\"invalid_token\"");
            }
            writeFailureStatus(response, status);
        } else {
            response.setStatus(HttpStatus.NO_CONTENT.value());
            noStore(response);
        }
    }

    protected void writeFailureStatus(HttpServletResponse response, HttpStatus status) throws IOException {
        response.setStatus(status.value());
        noStore(response);
        response.flushBuffer();
    }

    protected void noStore(HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
    }
}
