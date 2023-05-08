package com.example.challenge_chapter_4.Repository;

import com.example.challenge_chapter_4.Model.StudioEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;


@Repository
public interface StudioInterface extends JpaRepository<StudioEntity, Character>{
    Page<StudioEntity> findAll(Pageable pageable);


//    @Query("SELECT t,s FROM StudioEntity t JOIN SeatsEntity s WHERE t.studio_name = :studio_name AND s.nomor_kursi = :nomor_kursi")
//    StudioEntity getByStudio(@Param("studio_name") char studio_name, @Param("nomor_kursi") int nomor_kursi);
      //@Query("SELECT t FROM StudioEntity t JOIN SeatsEntity s WHERE s.nomor_kursi =:nomer_kursi AND t.studio_name =:studio_name")

}
