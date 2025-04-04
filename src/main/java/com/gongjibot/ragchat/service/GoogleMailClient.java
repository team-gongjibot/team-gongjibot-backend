package com.gongjibot.ragchat.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import java.util.function.Consumer;

@Component
@Profile("local")
public class GoogleMailClient implements MailClient {
    private final JavaMailSender mailSender;
    private final String fromEmail;

    public GoogleMailClient(JavaMailSender mailSender, @Value("${spring.mail.username}") String fromEmail) {
        this.mailSender = mailSender;
        this.fromEmail = fromEmail;
    }

    @Override
    @Async
    public void sendMail(Consumer<SimpleMailMessage> mailMessageConsumer) {
        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, "UTF-8");
            
            SimpleMailMessage simpleMailMessage = new SimpleMailMessage();
            mailMessageConsumer.accept(simpleMailMessage);
            
            helper.setTo(simpleMailMessage.getTo());
            helper.setSubject(simpleMailMessage.getSubject());
            helper.setText(simpleMailMessage.getText(), true);  // true는 HTML 활성화를 의미
            helper.setFrom(fromEmail);
            
            mailSender.send(mimeMessage);
        } catch (MessagingException e) {
            throw new RuntimeException("Failed to send email", e);
        }
    }
}
