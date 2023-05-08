package com.example.challenge_chapter_4.Model;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Entity
@Data
@Table(name = "users")
@Getter
@Setter
public class UsersEntity {
    @Id
    private int id_user;
    private String username;
    private String email;
    private String password;
    private String roles;
}
