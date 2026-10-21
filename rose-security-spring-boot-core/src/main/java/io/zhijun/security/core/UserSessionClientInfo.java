package io.zhijun.security.core;

/** Non-secret client metadata captured when a token session is created. */
public record UserSessionClientInfo(String clientIp, String device) {}
