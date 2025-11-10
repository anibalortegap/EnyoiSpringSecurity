package co.enyoi.authentication.config;

import co.enyoi.authentication.service.JpaUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final JpaUserDetailsService jpaUserDetailsService;

    private final jwtAuthenticationFilter jwtAuthenticationFilter;

    public SecurityConfig(JpaUserDetailsService jpaUserDetailsService, jwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jpaUserDetailsService = jpaUserDetailsService;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    //PasswordEncoder
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }


    //SecurityFilterChain - Filter Chain (Chain Responsibility)
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorizeRequests -> authorizeRequests
                        .requestMatchers("/h2-console/**", "/api/v1/auth/**", "/api/v1/refresh/**", "/api/v1/gateway/auth/**").permitAll()
                        .requestMatchers("/api/v1").permitAll()
                        .requestMatchers("/api/v1/private/admin/health").hasRole("ADMIN")
                        .requestMatchers("/api/v1/private/admin/write/health").hasAuthority("WRITE")
                        .anyRequest().authenticated())
                .userDetailsService(jpaUserDetailsService)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .headers(headers -> headers.frameOptions().sameOrigin())
                //.csrf(csrf -> csrf.ignoringRequestMatchers("/h2-console/**"));
                .csrf(csrf -> csrf.disable());


        return http.build();
    }
}
