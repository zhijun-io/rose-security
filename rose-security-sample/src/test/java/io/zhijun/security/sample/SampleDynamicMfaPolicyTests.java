package io.zhijun.security.sample;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.zhijun.security.autoconfigure.EmailMfaService;
import io.zhijun.security.core.MfaEmailSender;
import io.zhijun.security.core.MfaPolicy;
import io.zhijun.security.core.MfaPolicyProvider;
import io.zhijun.security.core.UserSessionService;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.json.JsonMapper;

@SpringBootTest(properties = "auth.security.mfa.enabled=false")
@AutoConfigureMockMvc
@Import(SampleDynamicMfaPolicyTests.DynamicPolicyConfiguration.class)
class SampleDynamicMfaPolicyTests {

    private static final String USERNAME = "demo@example.test";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JsonMapper jsonMapper;

    @Autowired
    private EmailMfaService emailMfaService;

    @Autowired
    private SampleMfaStore mfaStore;

    @Autowired
    private UserSessionService userSessionService;

    @Autowired
    private RecordingEmailSender emailSender;

    @BeforeEach
    void clearState() {
        mfaStore.clearEmailMfa(USERNAME);
        userSessionService.revokeAll(USERNAME);
        emailSender.code = null;
    }

    @Test
    void customPolicyCanRequireMfaWhenStaticMfaIsDisabled() throws Exception {
        EmailMfaService.Challenge enrollment =
                emailMfaService.beginEnrollment(USERNAME, Duration.ofMinutes(5), Instant.now());
        assertThat(emailMfaService.confirmEnrollment(USERNAME, enrollment.token(), emailSender.code, Instant.now(), 5))
                .isTrue();

        MvcResult pending = mockMvc.perform(post("/api/auth/login")
                        .servletPath("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"demo@example.test\",\"password\":\"password\"}"))
                .andExpect(status().isAccepted())
                .andReturn();
        var transaction = jsonMapper.readTree(pending.getResponse().getContentAsString());
        assertThat(transaction.get("methods").toString()).contains("email");

        MvcResult completed = mockMvc.perform(post("/api/auth/mfa/verify")
                        .servletPath("/api/auth/mfa/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonMapper.writeValueAsString(Map.of(
                                "transaction_token",
                                transaction.get("transaction_token").asString(),
                                "method",
                                "email",
                                "proof",
                                emailSender.code))))
                .andExpect(status().isOk())
                .andReturn();
        var tokenResponse = jsonMapper.readTree(completed.getResponse().getContentAsString());
        assertThat(tokenResponse.has("access_token")).isTrue();
        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/me/mfa")
                        .servletPath("/api/me/mfa")
                        .header(
                                "Authorization",
                                "Bearer " + tokenResponse.get("access_token").asString()))
                .andExpect(status().isOk());
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class DynamicPolicyConfiguration {

        @Bean
        @Primary
        MfaPolicyProvider dynamicMfaPolicy(EmailMfaService emailMfaService) {
            return user -> {
                boolean enabled = emailMfaService.isEnabled(user.getUsername());
                return new MfaPolicy(enabled, enabled ? Set.of("email") : Set.of(), Duration.ofMinutes(5));
            };
        }

        @Bean
        @Primary
        RecordingEmailSender recordingEmailSender() {
            return new RecordingEmailSender();
        }
    }

    static class RecordingEmailSender implements MfaEmailSender {

        private String code;

        @Override
        public void send(String email, String code, Instant expiresAt) {
            this.code = code;
        }
    }
}
