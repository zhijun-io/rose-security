package io.zhijun.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import tools.jackson.databind.json.JsonMapper;

class JsonAuthenticationConvertersTests {

    private final JsonMapper jsonMapper = JsonMapper.builder().build();

    @Test
    void malformedLoginJsonBecomesGenericAuthenticationFailure() {
        assertAuthenticationFailure(new JsonLoginAuthenticationConverter(jsonMapper), "{");
    }

    @Test
    void malformedRefreshJsonBecomesGenericAuthenticationFailure() {
        assertAuthenticationFailure(new JsonRefreshTokenAuthenticationConverter(jsonMapper), "{");
    }

    @Test
    void loginRequiresEmailAndPassword() {
        JsonLoginAuthenticationConverter converter = new JsonLoginAuthenticationConverter(jsonMapper);

        assertAuthenticationFailure(converter, "{}");
        assertAuthenticationFailure(converter, "{\"email\":\" \",\"password\":\"secret\"}");
        assertAuthenticationFailure(converter, "{\"email\":\"user@example.test\",\"password\":\"\"}");
    }

    @Test
    void refreshRequiresANonBlankRefreshToken() {
        JsonRefreshTokenAuthenticationConverter converter = new JsonRefreshTokenAuthenticationConverter(jsonMapper);

        assertAuthenticationFailure(converter, "{}");
        assertAuthenticationFailure(converter, "{\"refresh_token\":\" \"}");
    }

    @Test
    void loginConvertsCredentialsToUnauthenticatedSpringToken() {
        var authentication = new JsonLoginAuthenticationConverter(jsonMapper)
                .convert(requestWithJson("{\"email\":\" user@example.test \",\"password\":\"secret\"}"));

        assertThat(authentication).isInstanceOf(UsernamePasswordAuthenticationToken.class);
        assertThat(authentication.getName()).isEqualTo("user@example.test");
        assertThat(authentication.getCredentials()).isEqualTo("secret");
        assertThat(authentication.isAuthenticated()).isFalse();
    }

    @Test
    void refreshConvertsTokenToUnauthenticatedRefreshRequest() {
        var authentication = new JsonRefreshTokenAuthenticationConverter(jsonMapper)
                .convert(requestWithJson("{\"refresh_token\":\"opaque-refresh-token\"}"));

        assertThat(authentication).isInstanceOf(RefreshRequestAuthenticationToken.class);
        assertThat(authentication.isAuthenticated()).isFalse();
        assertThat(((RefreshRequestAuthenticationToken) authentication).refreshToken())
                .isEqualTo("opaque-refresh-token");
    }

    private static void assertAuthenticationFailure(AuthenticationConverter converter, String json) {
        assertThatThrownBy(() -> converter.convert(requestWithJson(json)))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Authentication failed")
                .hasNoCause();
    }

    private static MockHttpServletRequest requestWithJson(String json) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContent(json.getBytes(StandardCharsets.UTF_8));
        return request;
    }
}
