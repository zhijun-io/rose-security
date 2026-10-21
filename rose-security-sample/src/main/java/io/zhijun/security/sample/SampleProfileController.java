package io.zhijun.security.sample;

import io.zhijun.security.core.UserSessionService;
import java.time.Instant;
import java.util.List;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Protected endpoint used by the browser demo to prove that its Access Token is accepted. */
@RestController
public class SampleProfileController {

    private final UserSessionService userSessionService;

    public SampleProfileController(UserSessionService userSessionService) {
        this.userSessionService = userSessionService;
    }

    @GetMapping("/api/sample/profile")
    ProfileResponse profile(Authentication authentication) {
        Jwt jwt = (Jwt) authentication.getPrincipal();
        return new ProfileResponse(
                jwt.getSubject(),
                jwt.getClaimAsString("sid"),
                jwt.getClaimAsStringList("amr"),
                Instant.ofEpochSecond(((Number) jwt.getClaim("auth_time")).longValue()));
    }

    @GetMapping("/api/sample/sessions")
    UserSessionsResponse sessions(Authentication authentication) {
        Jwt jwt = (Jwt) authentication.getPrincipal();
        String currentSessionId = jwt.getClaimAsString("sid");
        List<UserSessionResponse> sessions = userSessionService.findActiveSessions(authentication.getName()).stream()
                .map(session -> new UserSessionResponse(
                        session.sessionId(),
                        session.createdAt(),
                        session.lastUsedAt(),
                        session.expiresAt(),
                        session.absoluteExpiresAt(),
                        session.device(),
                        session.clientIp(),
                        session.sessionId().equals(currentSessionId)))
                .toList();
        return new UserSessionsResponse(sessions);
    }

    record ProfileResponse(
            String email, String sessionId, List<String> authenticationMethods, Instant authenticatedAt) {}

    record UserSessionsResponse(List<UserSessionResponse> sessions) {}

    record UserSessionResponse(
            String sessionId,
            Instant createdAt,
            Instant lastUsedAt,
            Instant expiresAt,
            Instant absoluteExpiresAt,
            String device,
            String clientIp,
            boolean current) {}
}
