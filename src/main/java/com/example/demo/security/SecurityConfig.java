package com.example.demo.security;

import com.example.demo.security.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    // Constructor-based dependency injection
    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    // Security filter chain to configure HTTP security and authorization
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))  // Enable CORS
                .csrf(csrf -> csrf.disable())  // Disable CSRF protection for stateless API
                .authorizeHttpRequests(auth -> auth
                        // Public endpoints that don't require authentication
                        .requestMatchers(
                                "/api/auth/signup",
                                "/api/auth/login",
                                "/api/auth/send-otp",
                                "/api/auth/verify-otp",
                                "/api/test/**",
                                "/api/payment/**" // If payment creation doesn't require auth, keep this accessible
                        ).permitAll()

                        // Secure endpoints that require authentication
                        .requestMatchers("/api/payment/create-order").authenticated() // Secure this endpoint for authenticated users only
                        .requestMatchers("/api/auth/test/secure").authenticated() // Add more secure endpoints as needed

                        // All other endpoints require authentication
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)  // Stateless session (no HTTP session)
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);  // Add JWT filter before the default authentication filter

        return http.build();
    }

    // BCryptPasswordEncoder bean definition to enable password encoding
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();  // Define BCryptPasswordEncoder bean for password hashing
    }

    // AuthenticationManager bean definition for managing authentication
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();  // Retrieve the AuthenticationManager from Spring Security's configuration
    }

    // CORS configuration to enable cross-origin requests
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);  // Allow credentials (cookies, headers, etc.)
        config.setAllowedOrigins(List.of("http://localhost:3000", "http://your-other-frontend-url.com"));  // Allow specific origins (adjust for production)
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));  // Allow specific HTTP methods
        config.setAllowedHeaders(List.of("Authorization", "Content-Type"));  // Allow specific headers
        config.setExposedHeaders(List.of("Authorization"));  // Expose the Authorization header for frontend use

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);  // Apply the CORS configuration to all endpoints
        return source;
    }
}
