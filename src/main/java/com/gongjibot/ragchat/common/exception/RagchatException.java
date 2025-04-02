package com.gongjibot.ragchat.common.exception;

import lombok.Getter;
import org.springframework.core.NestedRuntimeException;

/**
 * NestedRuntimeException을 상속받아 사용함으로써 Spring Framework와 자연스러운 통합을 제공하고
 * 프로젝트에 맞는 공통 예외 처리 로직을 구현한다.
 */
@Getter
public abstract class RagchatException extends NestedRuntimeException {

    private final ErrorCode errorCode;

    protected RagchatException(ErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
    }

    protected RagchatException(ErrorCode errorCode, Throwable cause) {
        super(errorCode.getMessage(), cause);
        this.errorCode = errorCode;
    }

    protected RagchatException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }
}
