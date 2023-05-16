package com.example.challenge_chapter_4.Model;

import com.example.challenge_chapter_4.token.TokenEntity;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "users")
public class UsersEntity implements UserDetails {
    @Id
    private int id_user;
    private String username;
    private String email;
    private String password;
    private String roles;

    @Transient
    private List<GrantedAuthority> authorities;
    @OneToMany(mappedBy = "users")
    private List<TokenEntity> tokens;


    public UsersEntity(UsersEntity userinfo) {
        username = userinfo.getUsername();
        password = userinfo.getPassword();
        authorities = Arrays.stream(userinfo.getRoles().split(","))
                .map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
