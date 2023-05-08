package com.example.challenge_chapter_4.Repository;

import com.example.challenge_chapter_4.Model.JadwalEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface JadwalInterface extends JpaRepository<JadwalEntity, Integer> {
    Page<JadwalEntity> findAll(Pageable pageable);
}
