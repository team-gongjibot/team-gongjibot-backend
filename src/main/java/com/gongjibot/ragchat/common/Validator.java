package com.gongjibot.ragchat.common;

import com.gongjibot.ragchat.common.exception.ValidException;

public class Validator {
    private Validator() { // private 생성자를 통해 외부에서 인스턴스화 하지 못하게 막음
    }

    /**
     * 문자열이 null 또는 공백인지 검사합니다.
     *
     * @param input     검증할 문자열
     * @param fieldName 예외 메시지에 출력할 필드명
     * @throws ValidException input이 null 또는 공백이면
     */
    public static void notBlank(String input, String fieldName) {
        if (input == null || input.isBlank()) {
            throw new ValidException("%s은/는 null 또는 공백이 될 수 없습니다.".formatted(fieldName));
        }
    }

    /**
     * 문자열의 최대 길이를 검증합니다. null 값은 무시됩니다. 최대 길이가 0 이하이면 예외를 던집니다. 문자열의 길이가 maxLength 이하이면 예외를 던지지 않습니다.
     *
     * @param input     검증할 문자열
     * @param maxLength 검증할 문자열의 최대 길이
     * @param fieldName 예외 메시지에 출력할 필드명
     * @throws ValidException input의 길이가 maxLength 초과하면
     */
    public static void maxLength(CharSequence input, int maxLength, String fieldName) {
        if (maxLength <= 0) {
            throw new ValidException("최대 길이는 0 이하일 수 없습니다.");
        }
        // avoid NPE
        if (input == null) {
            return;
        }
        if (input.length() > maxLength) {
            throw new ValidException("%s의 길이는 %d글자 이하여야 합니다.".formatted(fieldName, maxLength));
        }
    }

    /**
     * 문자열의 최소 길이를 검증합니다. null 값은 무시됩니다. 최소 길이가 0 이하이면 예외를 던집니다. 문자열의 길이가 minLength보다 이상이면 예외를 던지지 않습니다.
     *
     * @param input     검증할 문자열
     * @param minLength 검증할 문자열의 최소 길이
     * @param fieldName 예외 메시지에 출력할 필드명
     * @throws ValidException input의 길이가 minLength 미만이면
     */
    public static void minLength(CharSequence input, int minLength, String fieldName) {
        if (minLength <= 0) {
            throw new ValidException("최소 길이는 0 이하일 수 없습니다.");
        }
        // avoid NPE
        if (input == null) {
            return;
        }
        if (input.length() < minLength) {
            throw new ValidException("%s의 길이는 %d글자 이상이어야 합니다.".formatted(fieldName, minLength));
        }
    }
}
