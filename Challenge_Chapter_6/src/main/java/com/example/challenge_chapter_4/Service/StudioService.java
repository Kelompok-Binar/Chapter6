package com.example.challenge_chapter_4.Service;

import com.example.challenge_chapter_4.Model.StudioEntity;
import com.example.challenge_chapter_4.Repository.StudioInterface;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class StudioService {
    @Autowired
    StudioInterface R;


    public Page<StudioEntity> getAll(int pageNumber, int pageSize) {
        Pageable pageable = PageRequest.of(pageNumber, pageSize);

        return R.findAll(pageable);
    }

//    public StudioEntity getByStudio(char studio, int seats){
//        return R.getByStudio(studio,seats);
//    }
}
