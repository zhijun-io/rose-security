package io.zhijun.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class UserSessionLogoutSuccessHandlerTests {

    @Test
    void writesNoContentForSuccessfulLogout() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        new UserSessionLogoutSuccessHandler().onLogoutSuccess(new MockHttpServletRequest(), response, null);

        assertThat(response.getStatus()).isEqualTo(HttpStatus.NO_CONTENT.value());
        assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
        assertThat(response.getHeader("Pragma")).isEqualTo("no-cache");
    }

    @Test
    void writesUnauthorizedAndBearerChallengeForInvalidToken() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(UserSessionLogoutHandler.FAILURE_ATTRIBUTE, HttpStatus.UNAUTHORIZED);
        MockHttpServletResponse response = new MockHttpServletResponse();

        new UserSessionLogoutSuccessHandler().onLogoutSuccess(request, response, null);

        assertThat(response.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
        assertThat(response.getHeader("WWW-Authenticate")).isEqualTo("Bearer error=\"invalid_token\"");
        assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
    }

    @Test
    void writesOtherLogoutFailureStatusWithoutBearerChallenge() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(UserSessionLogoutHandler.FAILURE_ATTRIBUTE, HttpStatus.FORBIDDEN);
        MockHttpServletResponse response = new MockHttpServletResponse();

        new UserSessionLogoutSuccessHandler().onLogoutSuccess(request, response, null);

        assertThat(response.getStatus()).isEqualTo(HttpStatus.FORBIDDEN.value());
        assertThat(response.getHeader("WWW-Authenticate")).isNull();
        assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
    }
}
