package io.zhijun.security.autoconfigure;

import io.zhijun.security.core.UserSessionClientInfo;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import ua_parser.Client;
import ua_parser.Parser;

public class DefaultUserSessionClientInfoDetailsSource
        implements AuthenticationDetailsSource<HttpServletRequest, UserSessionClientInfo> {

    private static final int MAX_USER_AGENT_LENGTH = 512;
    private static final Parser USER_AGENT_PARSER = new Parser();

    @Override
    public UserSessionClientInfo buildDetails(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        return new UserSessionClientInfo(resolveClientIp(request), describeDevice(userAgent));
    }

    protected String resolveClientIp(HttpServletRequest request) {
        return request.getRemoteAddr();
    }

    protected String describeDevice(String userAgent) {
        if (userAgent == null || userAgent.isBlank()) {
            return "未知设备";
        }
        String boundedUserAgent =
                userAgent.length() > MAX_USER_AGENT_LENGTH ? userAgent.substring(0, MAX_USER_AGENT_LENGTH) : userAgent;
        Client client = USER_AGENT_PARSER.parse(boundedUserAgent);
        String browser = knownOr(client.userAgent.family, "其他浏览器");
        String operatingSystem = knownOr(client.os.family, "未知系统");
        return browser + " · " + operatingSystem;
    }

    private static String knownOr(String value, String fallback) {
        return value == null || value.isBlank() || "Other".equalsIgnoreCase(value) ? fallback : value;
    }
}
