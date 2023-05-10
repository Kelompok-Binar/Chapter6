package com.example.challenge_chapter_4.Service;


import com.example.challenge_chapter_4.Model.UsersEntity;
import com.example.challenge_chapter_4.Repository.UsersInterface;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class UsersService {
    @Autowired
    private UsersInterface R;
    @Autowired
    private PasswordEncoder passwordEncoder;

    public Page<UsersEntity> getAll(int pageNumber, int pageSize){
        Pageable pageable = PageRequest.of(pageNumber, pageSize);

        return R.findAll(pageable);
    }
    public UsersEntity getById(int id_user){
        return R.findById(id_user).get();
    }

    public UsersEntity updateUser(UsersEntity param) {
        UsersEntity userExist =  R.findById(param.getId_user()).get();
        userExist.setUsername(param.getUsername());
        userExist.setEmail(param.getEmail());
        userExist.setPassword(param.getPassword());
        return R.save(userExist);
    }

    public UsersEntity addUsers(UsersEntity param) {
        Optional<UsersEntity> userExsist = R.findById(param.getId_user());
        if(userExsist.isPresent()){
            throw new RuntimeException("User ID " +param.getId_user() + " Sudah Ada");
        }
        else{
            param.setPassword(passwordEncoder.encode(param.getPassword()));
            return R.save(param);
        }

    }

    public List<UsersEntity> addMultipleUsers(List<UsersEntity> param) {
        List<UsersEntity> list = new ArrayList<>();

        for(UsersEntity user : param){
            Optional<UsersEntity> userExsist = R.findById(user.getId_user());
            if(userExsist.isPresent()){
                throw new RuntimeException("User ID " +user.getId_user() + " Sudah Ada");
            }
            else{
                user.setPassword(passwordEncoder.encode(user.getPassword()));
                list.add(R.save(user));
            }
        }
        return list;
    }


    public UsersEntity delUser(int param){
        UsersEntity delete = R.findById(param).get();
        R.deleteById(param);
        return delete;
    }
}
