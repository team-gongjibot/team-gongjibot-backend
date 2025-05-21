package com.gongjibot.ragchat.common.exception;

import java.time.LocalDateTime;

public record ErrorResponse(
  String code,
  String message,
  LocalDateTime timestamp
) {
  public ErrorResponse(ErrorCode errorCode) {
    this(errorCode.name(), errorCode.getMessage(), LocalDateTime.now());
  }
  
  public ErrorResponse(String code, String message) {
    this(code, message, LocalDateTime.now());
  }
} 