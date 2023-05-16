package com.example.challenge_chapter_4.Security;

import com.example.challenge_chapter_4.JWT.JwtAuthenticationFilter;
import jakarta.servlet.Filter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class WebSecurityConfig{
    private JwtAuthenticationFilter jwtAuthFilter;
    private AuthenticationProvider authenticationProvider;
    private LogoutHandler logoutHandler;

    @Bean
    public UserDetailsService userDetailsService(){
//        UserDetails admin = User.withUsername("diva").password("juan").roles("ADMIN").build();
//        UserDetails user = User.withUsername("j").password("j").roles("USER").build();
//        return new InMemoryUserDetailsManager(admin,user);
        //atas ini kalo secara manual, yang bawah secara Database
        return new UserInfoUserDetailsService();
    }
    @Bean
    public AuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.csrf()
                .disable()
                .authorizeHttpRequests()
                .requestMatchers("/Film","/Jadwal","/Studio",
                        "/Film/Judul-Film/{film_name}","/Film/Tayang","/Film//Jadwal/{film_name}","/Seats/Studios/{studio}/{nomor_kursi}","/swagger-ui/**","/v3/api-docs/**", "/auth/**").permitAll()
                .and().authorizeHttpRequests().requestMatchers("/Seats/**","/Users/**","/Film/**","/Jadwal/**","/Report/**").authenticated().and().sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .logout()
                .logoutUrl("/auth/logout")
                .addLogoutHandler(logoutHandler)
                .logoutSuccessHandler((request, response, authentication) -> SecurityContextHolder.clearContext());
        return httpSecurity.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    //untuk encode password
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
