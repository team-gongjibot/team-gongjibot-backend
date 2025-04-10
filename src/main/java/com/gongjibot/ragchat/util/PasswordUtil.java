package com.gongjibot.ragchat.util;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class PasswordUtil {
    
    private static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    private static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String NUMBERS = "0123456789";
    private static final String SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?";
    private static final int PASSWORD_LENGTH = 16;
    private static final SecureRandom RANDOM = new SecureRandom();

    public static String generateRandomPassword() {
        List<Character> passwordChars = new ArrayList<>();
        
        // 각 카테고리에서 최소 1개 이상의 문자를 포함
        passwordChars.add(getRandomChar(LOWERCASE));
        passwordChars.add(getRandomChar(UPPERCASE));
        passwordChars.add(getRandomChar(NUMBERS));
        passwordChars.add(getRandomChar(SPECIAL_CHARS));
        
        // 나머지 문자를 랜덤하게 선택
        String allChars = LOWERCASE + UPPERCASE + NUMBERS + SPECIAL_CHARS;
        for (int i = passwordChars.size(); i < PASSWORD_LENGTH; i++) {
            passwordChars.add(getRandomChar(allChars));
        }
        
        // 문자 순서를 랜덤하게 섞음
        Collections.shuffle(passwordChars, RANDOM);
        
        // StringBuilder를 사용하여 문자열 생성
        StringBuilder password = new StringBuilder();
        for (char c : passwordChars) {
            password.append(c);
        }
        
        return password.toString();
    }

    private static char getRandomChar(String source) {
        return source.charAt(RANDOM.nextInt(source.length()));
    }
}
