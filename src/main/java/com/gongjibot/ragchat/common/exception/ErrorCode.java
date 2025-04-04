package com.gongjibot.ragchat.common.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

import static org.springframework.http.HttpStatus.BAD_REQUEST;

@Getter
public enum ErrorCode {
    USER_NAME_DUPLICATED(BAD_REQUEST, "E001", "중복된 아이디입니다."),
    VALIDATION_FAIL(BAD_REQUEST, "E002", "검증에 실패하였습니다."),
    NICK_NAME_DUPLICATED(BAD_REQUEST, "E003", "중복된 닉네임입니다"),
    CERTIFICATION_FAIL(BAD_REQUEST, "E004", "이메일 인증에 실패하였습니다."),
    CERTIFICATION_MISMATCH(BAD_REQUEST, "E005", "인증코드가 일치하지 않습니다"),
    EMAIL_DUPLICATED(BAD_REQUEST, "E006", "중복된 이메일입니다."),
    USER_NOT_FOUND(BAD_REQUEST, "E007", "사용자를 찾을 수 없습니다")
    ;

    private HttpStatus status;
    private final String code;
    private final String message;

    ErrorCode(HttpStatus status, String code, String message) {
        this.status = status;
        this.code = code;
        this.message = message;
    }
}
