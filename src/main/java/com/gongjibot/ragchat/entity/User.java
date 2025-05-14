package com.gongjibot.ragchat.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.gongjibot.ragchat.common.BaseEntity;
import com.gongjibot.ragchat.common.Role;
import com.gongjibot.ragchat.common.SocialType;
import jakarta.persistence.*;
import jakarta.validation.constraints.Size;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User extends BaseEntity {
    private static final int MAX_NICKNAME_LENGTH = 30;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long id;

    @Column(name = "email", nullable = false)
    private String email;

    // OAuth 사용자는 null 가능
    @Column(name = "password")
    private String password;

    @Size(max = MAX_NICKNAME_LENGTH)
    @Column(name = "nickname", nullable = false)
    private String nickname;

    @Enumerated(EnumType.STRING)
    private Role role;

    @Enumerated(EnumType.STRING)
    private SocialType socialType; // KAKAO, GOOGLE, NAVER

    private String socialId;

    // OAuth 관련 필드
    // 일반 사용자는 모두 null 값을 가짐
    private String imageUrl;
    private int age;
    private String city;

    @JsonIgnore
    @OneToOne(fetch = FetchType.LAZY, cascade = CascadeType.ALL, orphanRemoval = true)
    @JoinColumn(name = "certification_id")
    private Certification certification;

    private String refreshToken;

    public void authorizeUser() {
        this.role = Role.USER;
    }

    public void updateRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public void updatePassword(String newPassword) {
        this.password = newPassword;
    }
    
    @Builder
    public User(String email, String password, String nickname, Role role,
                SocialType socialType, String socialId, String imageUrl, Certification certification) {
        this.email = email;
        this.password = password;
        this.nickname = nickname;
        this.role = role;
        this.socialType = socialType;
        this.socialId = socialId;
        this.imageUrl = imageUrl;
        this.certification = certification;
    }
}
