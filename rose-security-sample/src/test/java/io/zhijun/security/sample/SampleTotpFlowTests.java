package io.zhijun.security.sample;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import io.zhijun.security.core.UserSessionService;
import java.time.Instant;
import java.util.Map;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base32;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.json.JsonMapper;

@SpringBootTest
@AutoConfigureMockMvc
class SampleTotpFlowTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JsonMapper jsonMapper;

    @Autowired
    private SampleMfaStore mfaStore;

    @Autowired
    private UserSessionService userSessionService;

    @BeforeEach
    void clearDemoFactor() {
        mfaStore.remove("demo@example.test");
        userSessionService.revokeAll("demo@example.test");
    }

    @Test
    void bindsTotpUsesItAtLoginAndRequiresItsProofToRemoveIt() throws Exception {
        mockMvc.perform(get("/api/me/mfa").servletPath("/api/me/mfa")).andExpect(status().isUnauthorized());

        String primaryAccessToken = login().get("access_token").asString();
        mockMvc.perform(get("/api/me/mfa")
                        .servletPath("/api/me/mfa")
                        .header("Authorization", "Bearer " + primaryAccessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totpEnrolled").value(false));

        MvcResult enrollment = mockMvc.perform(post("/api/me/mfa/totp")
                        .servletPath("/api/me/mfa/totp")
                        .header("Authorization", "Bearer " + primaryAccessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonMapper.writeValueAsString(Map.of("password", "password"))))
                .andExpect(status().isOk())
                .andReturn();
        var enrollmentBody = jsonMapper.readTree(enrollment.getResponse().getContentAsString());
        String secret = enrollmentBody.get("secret").asString();
        assertFalse(secret.isBlank());
        assertTrue(enrollmentBody.get("otpauth_uri").asString().contains(secret));

        mockMvc.perform(post("/api/me/mfa/totp/verify")
                        .servletPath("/api/me/mfa/totp/verify")
                        .header("Authorization", "Bearer " + primaryAccessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonMapper.writeValueAsString(Map.of("code", code(secret, currentStep() - 1)))))
                .andExpect(status().isNoContent());
        assertFalse(userSessionService.findActiveSessions("demo@example.test").isEmpty());

        mockMvc.perform(get("/api/me/mfa")
                        .servletPath("/api/me/mfa")
                        .header("Authorization", "Bearer " + primaryAccessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totpEnrolled").value(true));

        var challenge = login();
        assertTrue(challenge.get("status").asString().equals("mfa_required"));
        assertFalse(challenge.has("access_token"));
        MvcResult completed = mockMvc.perform(post("/api/auth/mfa/verify")
                        .servletPath("/api/auth/mfa/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonMapper.writeValueAsString(Map.of(
                                "transaction_token",
                                challenge.get("transaction_token").asString(),
                                "method",
                                "totp",
                                "proof",
                                code(secret, currentStep())))))
                .andExpect(status().isOk())
                .andReturn();
        var tokens = jsonMapper.readTree(completed.getResponse().getContentAsString());
        String mfaAccessToken = tokens.get("access_token").asString();
        mockMvc.perform(delete("/api/me/mfa/totp")
                        .servletPath("/api/me/mfa/totp")
                        .header("Authorization", "Bearer " + primaryAccessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonMapper.writeValueAsString(Map.of("code", code(secret, currentStep() + 1)))))
                .andExpect(status().isNoContent());
        assertFalse(userSessionService.findActiveSessions("demo@example.test").isEmpty());

        mockMvc.perform(get("/api/me/mfa")
                        .servletPath("/api/me/mfa")
                        .header("Authorization", "Bearer " + mfaAccessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totpEnrolled").value(false));

        var loginWithoutTotp = login();
        assertTrue(loginWithoutTotp.has("access_token"));
        assertFalse(loginWithoutTotp.has("transaction_token"));
    }

    private tools.jackson.databind.JsonNode login() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .servletPath("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"demo@example.test\",\"password\":\"password\"}"))
                .andReturn();
        return jsonMapper.readTree(result.getResponse().getContentAsString());
    }

    private static String code(String base32Secret, long step) throws Exception {
        byte[] secret = new Base32().decode(base32Secret);
        String code = new TimeBasedOneTimePasswordGenerator()
                .generateOneTimePasswordString(new SecretKeySpec(secret, "HmacSHA1"), Instant.ofEpochSecond(step * 30));
        java.util.Arrays.fill(secret, (byte) 0);
        return code;
    }

    private static long currentStep() {
        return Math.floorDiv(Instant.now().getEpochSecond(), 30);
    }
}
