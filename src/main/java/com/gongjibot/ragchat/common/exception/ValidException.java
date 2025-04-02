package com.gongjibot.ragchat.common.exception;

/**
 * 구체적인 검증 예외 처리 및 특정 도메인의 예외 처리를 위해
 * 별도로 RagchatException을 상속받아 사용한다.
 */
public class ValidException extends RagchatException {
    public ValidException(String message) {
        super(ErrorCode.VALIDATION_FAIL, message);
    }
}
