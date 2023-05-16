package com.example.challenge_chapter_4.token;

import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface TokenRepo extends JpaRepository<TokenEntity, Integer> {

    @Query("""
      SELECT t FROM TokenEntity t INNER JOIN t.users u
      WHERE u.id_user = :id AND (t.expired = false OR t.revoked = false)
      """)
    List<TokenEntity> findAllValidTokenByUser(Integer id);

    Optional<TokenEntity> findByToken(String token);
}