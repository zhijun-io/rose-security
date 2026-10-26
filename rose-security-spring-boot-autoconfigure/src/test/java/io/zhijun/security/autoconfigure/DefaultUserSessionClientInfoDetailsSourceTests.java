package io.zhijun.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class DefaultUserSessionClientInfoDetailsSourceTests {

    @Test
    void usesRemoteAddressAndHandlesMissingOrUnknownUserAgents() {
        var source = new DefaultUserSessionClientInfoDetailsSource();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("192.0.2.5");

        var missing = source.buildDetails(request);
        assertThat(missing.clientIp()).isEqualTo("192.0.2.5");
        assertThat(missing.device()).isEqualTo("未知设备");

        request.addHeader("User-Agent", "unrecognized-client-token/1");
        assertThat(source.buildDetails(request).device()).contains("其他浏览器", "未知系统");
    }

    @Test
    void boundsOversizedUserAgentBeforeParsing() {
        var source = new DefaultUserSessionClientInfoDetailsSource();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("User-Agent", "x".repeat(10_000));

        assertThat(source.buildDetails(request).device()).isEqualTo("其他浏览器 · 未知系统");
    }
}
