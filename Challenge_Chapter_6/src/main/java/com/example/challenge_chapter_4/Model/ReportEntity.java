package com.example.challenge_chapter_4.Model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import java.sql.Date;
import java.sql.Time;
import java.util.List;

@Entity
@Data
@Table(name ="report")
@Getter
@Setter
public class ReportEntity {
    @Id
    private int id_report;
    private int id_jadwal;
    private String film_code;
    private String film_name;
    private String tayang_atau_tidak;
    private Date tanggal_tayang;
    private Time jam_mulai;
    private Time jam_selesai;
    private int harga_tiket;
    private int nomor_kursi;
    private char studio_name;
    @OneToMany(mappedBy = "film_code", cascade = CascadeType.ALL)
    private List<FilmEntity> jadwal;
    @OneToMany(mappedBy = "id_jadwal", cascade = CascadeType.ALL)
    private List<JadwalEntity> jadwal2;
    @OneToMany(mappedBy = "nomor_kursi", cascade = CascadeType.ALL)
    private List<SeatsEntity> jadwal3;
    @OneToMany(mappedBy = "studio_name", cascade = CascadeType.ALL)
    private List<StudioEntity> jadwal4;
}
