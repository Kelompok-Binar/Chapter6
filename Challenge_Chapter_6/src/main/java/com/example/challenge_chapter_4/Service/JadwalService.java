package com.example.challenge_chapter_4.Service;

import com.example.challenge_chapter_4.Model.JadwalEntity;
import com.example.challenge_chapter_4.Repository.JadwalInterface;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class JadwalService {
    @Autowired
    JadwalInterface R;
    public Page<JadwalEntity> getAll(int pageNumber, int pageSize) {
        Pageable pageable = PageRequest.of(pageNumber, pageSize);

        return R.findAll(pageable);
    }

    public JadwalEntity addJadwal(JadwalEntity param) {
        Optional<JadwalEntity> jadwalExsist = R.findById(param.getId_jadwal());
        if(jadwalExsist.isPresent()){
            throw new RuntimeException("Jadwal Id " + param.getId_jadwal() + " Sudah Ada") ;
        }
        else{
            return R.save(param);
        }

    }

    public List<JadwalEntity> addMultipleJadwal(List<JadwalEntity> param) {
        List<JadwalEntity> list = new ArrayList<>();

        for(JadwalEntity jadwal : param){
            Optional<JadwalEntity> jadwalExsist = R.findById(jadwal.getId_jadwal());
            if(jadwalExsist.isPresent()){
                throw new RuntimeException("Jadwal Id " +jadwal.getId_jadwal() + " Sudah ada");
            }
            else {
                list.add(R.save(jadwal));
            }
        }
        return list;
    }

    public JadwalEntity getById(int idJadwal) {
        return R.findById(idJadwal).get();
    }

    public JadwalEntity updateJadwal(JadwalEntity param) {
        JadwalEntity jadwalExsist = R.findById(param.getId_jadwal()).get();
        jadwalExsist.setFilm_code(param.getFilm_code());
        jadwalExsist.setHarga_tiket(param.getHarga_tiket());
        jadwalExsist.setTanggal_tayang(param.getTanggal_tayang());
        jadwalExsist.setJam_mulai(param.getJam_mulai());
        jadwalExsist.setJam_selesai(param.getJam_selesai());

        return R.save(jadwalExsist);

//        JadwalEntity schedulesEntity = R.findById(param.getId_jadwal()).get();
//        schedulesEntity.setScheduleId(param.getScheduleId());
//        schedulesEntity.setFilmCode(param.getFilmCode());
//        schedulesEntity.setTanggalTayang(param.getTanggalTayang());
//        schedulesEntity.setJamMulai(param.getJamMulai());
//        schedulesEntity.setJamSelesai(param.getJamSelesai());
//        schedulesEntity.setHargaTiket(param.getHargaTiket());
//        return schedulesRepo.save(schedulesEntity);

    }

    public JadwalEntity deleteJadwal(int idJadwal) {
        JadwalEntity delete = R.findById(idJadwal).get();
        R.deleteById(idJadwal);
        return delete;
    }


}
