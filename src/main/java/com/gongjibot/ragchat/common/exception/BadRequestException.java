package com.gongjibot.ragchat.common.exception;

public class BadRequestException extends RagchatException {
    public BadRequestException(ErrorCode errorCode) {
        super(errorCode);
    }
}
