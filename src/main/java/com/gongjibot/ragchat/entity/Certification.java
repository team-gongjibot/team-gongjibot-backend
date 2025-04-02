package com.gongjibot.ragchat.entity;

import com.gongjibot.ragchat.common.BaseEntity;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Certification extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "certification_id")
    private Long id;

    @Column(name = "email")
    private String email;

    @Embedded
    private VerificationCode verificationCode;

    @Builder
    public Certification(String email, VerificationCode verificationCode) {
        this.email = email;
        this.verificationCode = verificationCode;
    }
}
