package com.gongjibot.ragchat.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record PasswordResetDto(
        @NotBlank(message = "이메일은 필수입니다")
        @Email(message = "올바른 이메일 형식이 아닙니다")
        String email,

        @NotBlank(message = "인증코드는 필수입니다")
        String code,

        @NotBlank(message = "비밀번호는 필수입니다")
        @Pattern(regexp = "^(?=.*[a-zA-Z])(?=.*[0-9])(?=.*[#@$!%\\?&])[A-Za-z0-9#@$!%\\?&]{8,13}$", message = "비밀번호는 8~13자 영문 대소문자, 숫자, 특수문자를 사용하세요.")
        String newPassword
) {
}
