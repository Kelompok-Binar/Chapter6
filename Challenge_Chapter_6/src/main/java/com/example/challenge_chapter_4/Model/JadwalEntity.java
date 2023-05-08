package com.example.challenge_chapter_4.Model;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import java.sql.Date;
import java.sql.Time;


@Entity
@Data
@Table(name = "jadwal")
@Getter
@Setter
public class JadwalEntity {
    @Id
    private int id_jadwal;
    private String film_code;
    private Date tanggal_tayang;
    private Time jam_mulai;
    private Time jam_selesai;
    private int harga_tiket;

}
