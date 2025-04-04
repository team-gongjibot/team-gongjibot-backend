package com.gongjibot.ragchat.repository;

import com.gongjibot.ragchat.entity.Certification;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface CertificationRepository extends JpaRepository<Certification, Long> {
    Optional<Certification> findFirstByEmailOrderByCreateDateDesc(String email);

    void deleteByEmail(String email);
}
