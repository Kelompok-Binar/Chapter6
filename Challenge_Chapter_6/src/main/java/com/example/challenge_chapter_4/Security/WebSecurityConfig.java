package com.example.challenge_chapter_4.Security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class WebSecurityConfig{
    @Bean
    public UserDetailsService userDetailsService(){
//        UserDetails admin = User.withUsername("diva").password(encoder.encode("juan")).roles("ADMIN").build();
//        UserDetails user = User.withUsername("j").password(encoder.encode("j")).roles("USER").build();
//        return new InMemoryUserDetailsManager(admin,user);
        //atas ini kalo secara manual, yang bawah secara Database
        return new UserInfoUserDetailsService();
    }
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity.csrf().disable().authorizeHttpRequests().requestMatchers("/Film").permitAll()
                .and().authorizeHttpRequests().requestMatchers("/Film/Judul-Film/{film_name}").permitAll()
                //.and().authorizeHttpRequests().requestMatchers("/Film/Tayang").permitAll()
                .and().authorizeHttpRequests().requestMatchers("/Film/Jadwal/{film_name}").permitAll()
                .and().authorizeHttpRequests().requestMatchers("/Film/**").authenticated().and().formLogin().and().build();
    }

    @Bean
    //untuk encode password
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }
}
