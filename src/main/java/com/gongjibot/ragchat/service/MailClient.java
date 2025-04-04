package com.gongjibot.ragchat.service;

import org.springframework.mail.SimpleMailMessage;

import java.util.function.Consumer;

public interface MailClient {
    void sendMail(Consumer<SimpleMailMessage> mailMessageConsumer);
}
