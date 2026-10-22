package io.zhijun.security.sample;

import io.zhijun.security.core.MfaEmailSender;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

/** Sends sample MFA codes to Mailpit; the code is never written to application logs. */
@Component
public class SampleMfaEmailSender implements MfaEmailSender {

    private final JavaMailSender mailSender;

    public SampleMfaEmailSender(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    @Override
    public void send(String email, String code, Instant expiresAt) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setSubject("Rose Security verification code");
        message.setText("Your verification code is " + code + ". It expires at "
                + expiresAt.truncatedTo(ChronoUnit.SECONDS) + ". If you did not request it, ignore this message.");
        mailSender.send(message);
    }
}
