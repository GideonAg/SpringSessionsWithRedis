package org.redeemerlives.demosessioncourse.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;

import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{

        return httpSecurity.csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(request -> {
                    CorsConfiguration configuration = new CorsConfiguration();
                    configuration.setAllowCredentials(true);
//                    configuration.addAllowedOrigin("*");
                    configuration.addAllowedOrigin(null);
                    configuration.setAllowedHeaders(List.of("*"));
                    configuration.setAllowedMethods(List.of("*"));
                    return configuration;
                }))
                .authorizeHttpRequests(requests -> requests
                        .requestMatchers("/api/login", "/api/logout", "/api/register")
                        .permitAll()
                        .anyRequest()
                        .authenticated()
                )
                .sessionManagement(sessions -> sessions
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(true))
                .authenticationProvider(authenticationProvider)
                .build();
    }
}
