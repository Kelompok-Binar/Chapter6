package com.example.challenge_chapter_4.Model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Entity
@Data
@Table(name = "film")
@Getter
@Setter
public class FilmEntity {


    @Id
    private String film_code;
    private String film_name;
    private String tayang_atau_tidak;

    @OneToMany(mappedBy = "film_code", cascade = CascadeType.ALL)
    private List<JadwalEntity> jadwal;

}
