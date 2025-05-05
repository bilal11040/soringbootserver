package com.example.demo.dto;

public class AuthResponse {
    private String token;
    private String message;
    private String username;
    private String email;

    // ✅ Corrected constructor to include username and email
    public AuthResponse(String token, String message, String username, String email) {
        this.token = token;
        this.message = message;
        this.username = username;
        this.email = email;
    }

    public String getToken() { return token; }
    public void setToken(String token) { this.token = token; }

    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; } // ✅ Added setter

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; } // ✅ Added setter
}
