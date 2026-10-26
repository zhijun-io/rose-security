package io.zhijun.security.sample;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.zhijun.security.core.MfaEmailSender;
import io.zhijun.security.core.UserSessionService;
import java.time.Instant;
import java.util.Map;
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

@SpringBootTest(properties = "auth.security.mfa.methods=email")
@AutoConfigureMockMvc
@Import(SampleEmailMfaFlowTests.EmailSenderConfiguration.class)
class SampleEmailMfaFlowTests {

    private static final String USERNAME = "demo@example.test";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JsonMapper jsonMapper;

    @Autowired
    private SampleMfaStore mfaStore;

    @Autowired
    private UserSessionService userSessionService;

    @Autowired
    private RecordingEmailSender emailSender;

    @BeforeEach
    void clearDemoFactor() {
        mfaStore.clearEmailMfa(USERNAME);
        userSessionService.revokeAll(USERNAME);
        emailSender.code = null;
    }

    @Test
    void enrollmentLoginAndRemovalRequireEmailProofWithoutLoggingOut() throws Exception {
        String accessToken = login().get("access_token").asString();

        mockMvc.perform(post("/api/me/mfa/totp")
                        .servletPath("/api/me/mfa/totp")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isNotFound());

        MvcResult enrollment = mockMvc.perform(post("/api/me/mfa/email")
                        .servletPath("/api/me/mfa/email")
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isOk())
                .andReturn();
        String enrollmentToken = jsonMapper
                .readTree(enrollment.getResponse().getContentAsString())
                .get("challenge_token")
                .asString();
        assertThat(emailSender.code).matches("[0-9]{6}");

        mockMvc.perform(post("/api/me/mfa/email/verify")
                        .servletPath("/api/me/mfa/email/verify")
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonMapper.writeValueAsString(
                                Map.of("challenge_token", enrollmentToken, "code", emailSender.code))))
                .andExpect(status().isNoContent());
        assertThat(mfaStore.isEnabled(USERNAME)).isTrue();

        MvcResult pendingLogin = mockMvc.perform(post("/api/auth/login")
                        .servletPath("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"demo@example.test\",\"password\":\"password\"}"))
                .andExpect(status().isAccepted())
                .andReturn();
        var pending = jsonMapper.readTree(pendingLogin.getResponse().getContentAsString());
        assertThat(pending.get("methods").toString()).contains("email");
        String transactionToken = pending.get("transaction_token").asString();
        MvcResult completedLogin = mockMvc.perform(post("/api/auth/mfa/verify")
                        .servletPath("/api/auth/mfa/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonMapper.writeValueAsString(Map.of(
                                "transaction_token", transactionToken, "method", "email", "proof", emailSender.code))))
                .andExpect(status().isOk())
                .andReturn();
        String mfaAccessToken = jsonMapper
                .readTree(completedLogin.getResponse().getContentAsString())
                .get("access_token")
                .asString();

        MvcResult removal = mockMvc.perform(delete("/api/me/mfa/email")
                        .servletPath("/api/me/mfa/email")
                        .header("Authorization", "Bearer " + mfaAccessToken))
                .andExpect(status().isAccepted())
                .andReturn();
        String removalToken = jsonMapper
                .readTree(removal.getResponse().getContentAsString())
                .get("challenge_token")
                .asString();
        assertThat(mfaStore.isEnabled(USERNAME)).isTrue();

        mockMvc.perform(post("/api/me/mfa/email/remove/verify")
                        .servletPath("/api/me/mfa/email/remove/verify")
                        .header("Authorization", "Bearer " + mfaAccessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonMapper.writeValueAsString(
                                Map.of("challenge_token", removalToken, "code", emailSender.code))))
                .andExpect(status().isNoContent());

        mockMvc.perform(get("/api/me/mfa")
                        .servletPath("/api/me/mfa")
                        .header("Authorization", "Bearer " + mfaAccessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.emailEnabled").value(false));
        assertThat(userSessionService.findActiveSessions(USERNAME)).isNotEmpty();
        assertThat(login().has("access_token")).isTrue();
    }

    private tools.jackson.databind.JsonNode login() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .servletPath("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"demo@example.test\",\"password\":\"password\"}"))
                .andExpect(status().isOk())
                .andReturn();
        return jsonMapper.readTree(result.getResponse().getContentAsString());
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class EmailSenderConfiguration {

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
