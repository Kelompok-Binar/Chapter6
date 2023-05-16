package com.example.challenge_chapter_4.Auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {
    private int id_user;
    private String username;
    private String email;
    private String password;
    private String roles;
}
