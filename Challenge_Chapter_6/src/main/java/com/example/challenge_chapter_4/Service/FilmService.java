package com.example.challenge_chapter_4.Service;

import com.example.challenge_chapter_4.Model.FilmEntity;
import com.example.challenge_chapter_4.Repository.FilmInterface;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class FilmService {
    @Autowired
    FilmInterface R;

    public Page<FilmEntity> getAll(int pageNumber, int pageSize){

        Pageable pageable = PageRequest.of(pageNumber, pageSize);

        return R.findAll(pageable);
    }
    public List<FilmEntity> getByTitle(String film_name){
        return R.findByName(film_name);
    }

    public FilmEntity addFilm(FilmEntity param){
        Optional<FilmEntity> filmExsist = R.findById(param.getFilm_code());
        if(filmExsist.isPresent()){
            throw new RuntimeException("Film Code " + param.getFilm_code() + " Sudah Ada");
        }
        else {
            return R.save(param);
        }

    }

    public List<FilmEntity> addMultipleFilm(List<FilmEntity> param){
        List<FilmEntity> list = new ArrayList<>();

        for(FilmEntity film : param){
            Optional<FilmEntity> filmExsist = R.findById(film.getFilm_code());
            if(filmExsist.isPresent()){
                throw new RuntimeException("Film Code " + film.getFilm_code() + " Sudah Ada");
            }
            else {
                list.add(R.save(film));
            }
        }
        return list;
    }

    public FilmEntity updateFilm(FilmEntity param){
        FilmEntity filmExsist = R.findById(param.getFilm_code()).get();
        filmExsist.setFilm_name(param.getFilm_name());
        filmExsist.setTayang_atau_tidak(param.getTayang_atau_tidak());
        return R.save(filmExsist);
    }

    public FilmEntity delFilm(String param){
        FilmEntity delete = R.findById(param).get();
        R.deleteById(param);
        return delete;
    }

    public List<FilmEntity> getTayang() {
        return R.findFilmTayang();
    }

    public List<FilmEntity> getByFilmJadwal(String film_name){
        return R.getByFilmJadwal(film_name);
    }
}
