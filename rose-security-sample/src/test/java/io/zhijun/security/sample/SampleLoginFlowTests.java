package io.zhijun.security.sample;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.json.JsonMapper;

@SpringBootTest
@AutoConfigureMockMvc
@Import(SampleLoginFlowTests.PreferredAuthenticationManagerConfiguration.class)
class SampleLoginFlowTests {

    @Autowired
    private AuthenticationConfiguration authenticationConfiguration;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JsonMapper jsonMapper;

    @Autowired
    private AtomicInteger preferredManagerCalls;

    @Test
    void repeatedAuthenticationWithDemoCredentialsSucceeds() throws Exception {
        AuthenticationManager authenticationManager = authenticationConfiguration.getAuthenticationManager();
        for (int attempt = 0; attempt < 2; attempt++) {
            authenticationManager.authenticate(
                    UsernamePasswordAuthenticationToken.unauthenticated("demo@example.test", "password"));
        }
    }

    @Test
    void publishesPublicJwksWithoutAuthentication() throws Exception {
        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.keys[0].kid")
                        .value("sample-ephemeral"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.keys[0].d")
                        .doesNotExist());
    }

    @Test
    void rejectsUnknownDemoUsernames() throws Exception {
        AuthenticationManager authenticationManager = authenticationConfiguration.getAuthenticationManager();

        assertThrows(
                BadCredentialsException.class,
                () -> authenticationManager.authenticate(
                        UsernamePasswordAuthenticationToken.unauthenticated("other@example.test", "password")));
    }

    @Test
    void httpFiltersIssueTokensAndAcceptLogout() throws Exception {
        MvcResult login = mockMvc.perform(post("/api/auth/login")
                        .servletPath("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"demo@example.test\",\"password\":\"password\"}"))
                .andExpect(status().isOk())
                .andReturn();

        var tokens = jsonMapper.readTree(login.getResponse().getContentAsString());
        String accessToken = tokens.get("access_token").asString();
        String refreshToken = tokens.get("refresh_token").asString();
        assertFalse(accessToken.isBlank());
        assertFalse(refreshToken.isBlank());
        assertTrue(preferredManagerCalls.get() > 0);

        mockMvc.perform(post("/api/auth/refresh")
                        .servletPath("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonMapper.writeValueAsString(Map.of("refresh_token", refreshToken))))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/auth/logout")
                        .servletPath("/api/auth/logout")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isNoContent());
    }

    @Test
    void httpLoginFailureUsesTheHostsGenericAuthenticationResponse() throws Exception {
        MvcResult failure = mockMvc.perform(post("/api/auth/login")
                        .servletPath("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"unknown@example.test\",\"password\":\"wrong\"}"))
                .andExpect(status().isUnauthorized())
                .andReturn();

        String body = failure.getResponse().getContentAsString();
        assertFalse(body.contains("unknown@example.test"));
        assertFalse(body.contains("wrong"));
        assertTrue(failure.getResponse().getContentType().startsWith(MediaType.APPLICATION_PROBLEM_JSON_VALUE));
    }

    @Test
    void webAuthnRegistrationOptionsAreSerializedForTheBrowser() throws Exception {
        MvcResult login = mockMvc.perform(post("/api/auth/login")
                        .servletPath("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"demo@example.test\",\"password\":\"password\"}"))
                .andExpect(status().isOk())
                .andReturn();
        String accessToken = jsonMapper.readTree(login.getResponse().getContentAsString())
                .get("access_token")
                .asString();

        mockMvc.perform(post("/api/me/mfa/webauthn/register/options")
                        .servletPath("/api/me/mfa/webauthn/register/options")
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isOk())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.challengeToken")
                        .isNotEmpty())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.publicKey.challenge")
                        .isString())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath(
                                "$.publicKey.authenticatorSelection.userVerification")
                        .value("required"));
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class PreferredAuthenticationManagerConfiguration {

        @Bean
        AtomicInteger preferredManagerCalls() {
            return new AtomicInteger();
        }

        @Bean
        @Primary
        AuthenticationManager preferredAuthenticationManager(
                AuthenticationConfiguration authenticationConfiguration, AtomicInteger preferredManagerCalls)
                throws Exception {
            AuthenticationManager delegate = authenticationConfiguration.getAuthenticationManager();
            return authentication -> {
                preferredManagerCalls.incrementAndGet();
                return delegate.authenticate(authentication);
            };
        }
    }
}
