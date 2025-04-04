package com.gongjibot.ragchat.service;

import org.springframework.stereotype.Component;

@Component
public class EmailTemplateServiceImpl implements EmailTemplateService {
    @Override
    public String getVerificationEmailContent(String verificationCode) {
        return """
            <html>
                <body>
                    <h1>RAG Chatbot 이메일 인증</h1>
                    <p>안녕하세요. RAG Chatbot 팀입니다.</p>
                    <p>인증 코드는 다음과 같습니다:</p>
                    <h2>%s</h2>
                    <p>이 코드는 10분간 유효합니다.</p>
                </body>
            </html>
            """.formatted(verificationCode);
    }
}
