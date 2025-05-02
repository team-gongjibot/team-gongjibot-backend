package com.gongjibot.ragchat.dto;

import com.gongjibot.ragchat.common.VerificationPurpose;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

public record EmailCertificationRequestDto(
        @NotBlank(message = "이메일을 입력해주세요")
        @Email(message = "이메일 형식이 올바르지 않습니다.")
        @Pattern(regexp = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", message = "이메일 형식이 올바르지 않습니다.")
        String email,
        
        @NotNull(message = "인증 목적은 필수입니다")
        VerificationPurpose purpose
) {
}
