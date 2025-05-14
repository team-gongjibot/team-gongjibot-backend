package com.gongjibot.ragchat.service;

import com.gongjibot.ragchat.common.Role;
import com.gongjibot.ragchat.common.VerificationPurpose;
import com.gongjibot.ragchat.common.exception.BadRequestException;
import com.gongjibot.ragchat.common.exception.ErrorCode;
import com.gongjibot.ragchat.dto.*;
import com.gongjibot.ragchat.entity.Certification;
import com.gongjibot.ragchat.entity.User;
import com.gongjibot.ragchat.entity.VerificationCode;
import com.gongjibot.ragchat.repository.CertificationRepository;
import com.gongjibot.ragchat.repository.UserRepository;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final CertificationRepository certificationRepository;
    private final VerificationCodeProvider verificationCodeProvider;
    private final MailClient mailClient;
    private final EmailTemplateService emailTemplateService;

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final long LOCK_TIME_DURATION = 15 * 60 * 1000; // 15분

    @Transactional
    public void singUp(SignUpRequestDto dto) {
        String encodePassword = passwordEncoder.encode(dto.password());

        if (userRepository.findByNickname(dto.nickname()).isPresent()) {
            throw new BadRequestException(ErrorCode.NICK_NAME_DUPLICATED);
        }

        Certification certification = certificationRepository.findFirstByEmailOrderByCreateDateDesc(dto.email())
                .orElseThrow(() -> new BadRequestException(ErrorCode.CERTIFICATION_FAIL));

        boolean isMatched = certification.getEmail().equals(dto.email())
                && certification.getVerificationCode().getCode().equals(dto.verificationCode());

        if (!isMatched)
            throw new BadRequestException(ErrorCode.CERTIFICATION_MISMATCH);

        User user = User.builder()
                .email(dto.email())
                .password(encodePassword)
                .nickname(dto.nickname())
                .role(Role.USER)
                .build();

        userRepository.save(user);
        certificationRepository.deleteByEmail(dto.email());
    }

    @Transactional
    public void emailCertification(EmailCertificationRequestDto dto) {
        Certification certification = createCode(dto.email(), dto.purpose());
        sendMail(certification);
        certificationRepository.save(certification);
    }

    private Certification createCode(String email, VerificationPurpose purpose) {
        VerificationCode verificationCode = verificationCodeProvider.provide();

        switch (purpose) {
            case SIGN_UP:
                userRepository.findByEmail(email).ifPresent(
                        user -> {throw new BadRequestException(ErrorCode.EMAIL_DUPLICATED);}
                );
                break;
            case FIND_ID:
            case RESET_PASSWORD:
                userRepository.findByEmail(email).orElseThrow(
                        () -> new BadRequestException(ErrorCode.USER_NOT_FOUND)
                );
                break;
        }

        return Certification.builder()
                .email(email)
                .verificationCode(verificationCode)
                .build();
    }

    private void sendMail(Certification certification) {
        String content = emailTemplateService.getVerificationEmailContent(
                certification.getVerificationCode().getCode()
        );
        mailClient.sendMail(mail -> {
            mail.setTo(certification.getEmail());
            mail.setSubject("[RAG Chatbot] 이메일 인증 코드");
            mail.setText(content);
        });
    }

//    @Transactional
//    public String findId(FindIdRequestDto dto) {
//        User user = userRepository.findByEmail(dto.email())
//                .orElseThrow(() -> new BadRequestException(ErrorCode.USER_NOT_FOUND));
//
//        Certification certification = certificationRepository.findFirstByEmailOrderByCreateDateDesc(dto.email())
//                .orElseThrow(() -> new BadRequestException(ErrorCode.CERTIFICATION_FAIL));
//
//        boolean isMatched = certification.getVerificationCode().getCode().equals(dto.code());
//        if (!isMatched) throw new BadRequestException(ErrorCode.CERTIFICATION_MISMATCH);
//
//        certificationRepository.deleteByEmail(dto.email());
//        return user.getUsername();
//    }

    @Transactional
    public void passwordReset(PasswordResetDto dto) {
        // 사용자 정보 조회
        User user = userRepository.findByEmail(dto.email())
                .orElseThrow(() -> new BadRequestException(ErrorCode.USER_NOT_FOUND));

        // 인증 코드 확인
        Certification certification = certificationRepository
                .findFirstByEmailOrderByCreateDateDesc(dto.email())
                .orElseThrow(() -> new BadRequestException(ErrorCode.CERTIFICATION_FAIL));

        // 인증 코드 일치 여부 확인
        boolean isMatched = certification.getVerificationCode().getCode().equals(dto.code());
        if (!isMatched) throw new BadRequestException(ErrorCode.CERTIFICATION_MISMATCH);

        // 비밀번호 암호화 및 업데이트
        String encodedPassword = passwordEncoder.encode(dto.newPassword());
        user.updatePassword(encodedPassword);

        // 사용자 정보 저장
        userRepository.save(user);
        certificationRepository.deleteByEmail(dto.email());
    }
}
