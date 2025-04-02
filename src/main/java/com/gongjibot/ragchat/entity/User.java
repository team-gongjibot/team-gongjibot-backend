package com.gongjibot.ragchat.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import jakarta.validation.constraints.Size;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User {
    private static final int MAX_NICKNAME_LENGTH = 30;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long id;

    @Column(name = "username", nullable = false)
    private String username;

    @Column(name = "password", nullable = false)
    private String password;

    @Column(name = "email", nullable = false)
    private String email;

    @Size(max = MAX_NICKNAME_LENGTH)
    @Column(name = "nickname", nullable = false)
    private String nickname;

    @JsonIgnore
    @OneToOne(fetch = FetchType.LAZY, cascade = CascadeType.ALL, orphanRemoval = true)
    @JoinColumn(name = "certification_id")
    private Certification certification;

    @Builder
    public User(String username, String password, String email, String nickname, Certification certification) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.nickname = nickname;
        this.certification = certification;
    }
}
