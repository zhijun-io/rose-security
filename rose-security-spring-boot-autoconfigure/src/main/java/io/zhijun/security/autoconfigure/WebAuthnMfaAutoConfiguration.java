package io.zhijun.security.autoconfigure;

import io.zhijun.security.core.WebAuthnMfaChallengeStore;
import java.security.SecureRandom;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRpEntity;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.security.web.webauthn.management.WebAuthnRelyingPartyOperations;
import org.springframework.security.web.webauthn.management.Webauthn4JRelyingPartyOperations;
import tools.jackson.databind.json.JsonMapper;

/** Optional use of Spring Security's WebAuthn implementation for the MFA factor. */
@AutoConfiguration
@ConditionalOnClass(WebAuthnRelyingPartyOperations.class)
@ConditionalOnProperty(prefix = "auth.security.mfa", name = "enabled", havingValue = "true")
public class WebAuthnMfaAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(WebAuthnRelyingPartyOperations.class)
    @ConditionalOnBean({PublicKeyCredentialUserEntityRepository.class, UserCredentialRepository.class})
    @ConditionalOnProperty(prefix = "auth.security.mfa", name = "webauthn-rp-id")
    WebAuthnRelyingPartyOperations authSecurityWebAuthnRelyingPartyOperations(
            AuthSecurityProperties properties,
            PublicKeyCredentialUserEntityRepository users,
            UserCredentialRepository credentials) {
        var rp = PublicKeyCredentialRpEntity.builder()
                .id(properties.mfa().webauthnRpId())
                .name(properties.mfa().totpIssuer())
                .build();
        return new Webauthn4JRelyingPartyOperations(
                users, credentials, rp, properties.mfa().webauthnAllowedOrigins());
    }

    @Bean
    @ConditionalOnMissingBean(WebAuthnMfaService.class)
    @ConditionalOnBean({WebAuthnRelyingPartyOperations.class, WebAuthnMfaChallengeStore.class})
    WebAuthnMfaService authSecurityWebAuthnMfaService(
            WebAuthnRelyingPartyOperations relyingParty,
            PublicKeyCredentialUserEntityRepository users,
            UserCredentialRepository credentials,
            WebAuthnMfaChallengeStore challenges,
            JsonMapper jsonMapper,
            AuthSecurityProperties properties) {
        return new WebAuthnMfaService(
                relyingParty,
                users,
                credentials,
                challenges,
                jsonMapper,
                new SecureRandom(),
                properties.mfa().transactionTtl());
    }
}
