package com.gongjibot.ragchat.common.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

import static org.springframework.http.HttpStatus.BAD_REQUEST;

@Getter
public enum ErrorCode {
    USER_ID_DUPLICATED(BAD_REQUEST, "E001", "중복된 아이디입니다."),
    VALIDATION_FAIL(BAD_REQUEST, "E002", "검증에 실패하였습니다.")
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
