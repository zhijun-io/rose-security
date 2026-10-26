package io.zhijun.security.core;

import org.springframework.security.core.userdetails.UserDetails;

/** Resolves enabled, enrolled MFA methods for a user without defining the application's role model. */
@FunctionalInterface
public interface MfaPolicyProvider {

    MfaPolicy policyFor(UserDetails user);
}
