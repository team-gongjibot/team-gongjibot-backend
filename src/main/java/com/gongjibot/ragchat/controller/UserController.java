package com.gongjibot.ragchat.controller;

import com.gongjibot.ragchat.dto.*;
import com.gongjibot.ragchat.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @PostMapping("/sign-up")
    public ResponseEntity<Void> signUp(@RequestBody @Valid SignUpRequestDto requestBody) {
        userService.singUp(requestBody);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/email-certification")
    public ResponseEntity<Void> emailCertification(@RequestBody @Valid EmailCertificationRequestDto requestBody) {
        userService.emailCertification(requestBody);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/jwt-test")
    public String jwtTest() {
        return "jwtTest 요청 성공";
    }

    // @PostMapping("find-id")
    // public ResponseEntity<FindIdResponseDto> findId(@RequestBody @Valid FindIdRequestDto requestBody) {
    //     String username = userService.findId(requestBody);
    //     FindIdResponseDto responseDto = new FindIdResponseDto(username);
    //     return ResponseEntity.ok(responseDto);
    // }

    @PostMapping("/password-reset")
    public ResponseEntity<Void> passwordReset(@RequestBody @Valid PasswordResetDto requestBody) {
        userService.passwordReset(requestBody);
        return ResponseEntity.ok().build();
    }
}
