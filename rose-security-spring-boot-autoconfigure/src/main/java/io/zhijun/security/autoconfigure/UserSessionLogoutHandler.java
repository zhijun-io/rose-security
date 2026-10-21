package io.zhijun.security.autoconfigure;

import io.zhijun.security.core.UserSessionService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.web.authentication.logout.LogoutHandler;

/** Revokes one token session or all user sessions. */
public class UserSessionLogoutHandler implements LogoutHandler {

    static final String FAILURE_ATTRIBUTE = UserSessionLogoutHandler.class.getName() + ".failure";

    private final UserSessionService userSessionService;
    private final JwtDecoder jwtDecoder;
    private final String logoutAllPath;

    public UserSessionLogoutHandler(
            UserSessionService userSessionService, JwtDecoder jwtDecoder, String logoutAllPath) {
        this.userSessionService = userSessionService;
        this.jwtDecoder = jwtDecoder;
        this.logoutAllPath = logoutAllPath;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        boolean allSessions = logoutAllPath != null && logoutAllPath.equals(request.getServletPath());
        String authorization = request.getHeader("Authorization");
        if (authorization == null || !authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            request.setAttribute(FAILURE_ATTRIBUTE, HttpStatus.UNAUTHORIZED);
            return;
        }
        try {
            Jwt jwt = jwtDecoder.decode(authorization.substring(7).trim());
            String username = jwt.getSubject();
            String sessionId = jwt.getClaimAsString("sid");
            if (username == null
                    || username.isBlank()
                    || (!allSessions && (sessionId == null || sessionId.isBlank()))) {
                request.setAttribute(FAILURE_ATTRIBUTE, HttpStatus.UNAUTHORIZED);
                return;
            }
            if (allSessions) {
                userSessionService.revokeAll(username);
            } else {
                userSessionService.revoke(username, sessionId);
            }
        } catch (JwtException exception) {
            request.setAttribute(FAILURE_ATTRIBUTE, HttpStatus.UNAUTHORIZED);
        } catch (RuntimeException exception) {
            request.setAttribute(FAILURE_ATTRIBUTE, HttpStatus.SERVICE_UNAVAILABLE);
        }
    }
}
