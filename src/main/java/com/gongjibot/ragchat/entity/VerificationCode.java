package com.gongjibot.ragchat.entity;

import com.gongjibot.ragchat.common.Validator;
import com.gongjibot.ragchat.common.exception.ValidException;
import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.regex.Pattern;

@Getter
@Embeddable
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class VerificationCode {
    public static final int LENGTH = 6;
    private static final Pattern POSITIVE_REGEX = Pattern.compile("^\\d+$");

    @Column(name = "code")
    private String code;

    public VerificationCode(String code) {
        validate(code);
        this.code = code;
    }

    private void validate(String code) {
        validateBlank(code);
        validateLength(code);
        validatePositive(code);
    }

    private void validateBlank(String code) {
        Validator.notBlank(code, "VerificationCode");
    }

    private void validateLength(String code) {
        if (code.length() != LENGTH) {
            throw new ValidException("VerificationCode의 길이는 %d 이어야 합니다.".formatted(LENGTH));
        }
    }

    private void validatePositive(String code) {
        if (!POSITIVE_REGEX.matcher(code).matches()) {
            throw new ValidException("VerificationCode는 0 ~ 9의 양수 형식이어야 합니다.");
        }
    }
}
