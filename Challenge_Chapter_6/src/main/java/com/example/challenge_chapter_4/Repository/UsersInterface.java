package com.example.challenge_chapter_4.Repository;

import com.example.challenge_chapter_4.Model.UsersEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UsersInterface extends JpaRepository<UsersEntity, Integer> {
    Page<UsersEntity> findAll(Pageable pageable);

    Optional<UsersEntity> findByUsername(String username);
}
