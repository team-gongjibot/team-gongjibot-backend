package com.gongjibot.ragchat.service;

public interface EmailTemplateService {
    String getVerificationEmailContent(String verificationCode);
}
