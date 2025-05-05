package com.example.demo.controller;
import org.springframework.security.core.Authentication;

import com.example.demo.model.User;
import com.example.demo.dto.AuthRequest;
import com.example.demo.dto.AuthResponse;
import com.example.demo.dto.OtpRequest;
import com.example.demo.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "http://localhost:3000")
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody AuthRequest request) {
        authService.initiateSignup(request.getUsername(), request.getEmail(), request.getPassword());
        return ResponseEntity.ok("OTP sent to email. Please verify.");
    }

    @PostMapping("/send-otp")
    public ResponseEntity<String> sendOtp(@RequestBody OtpRequest request) {
        authService.initiateSignup(request.getUsername(), request.getEmail(), request.getPassword());
        return ResponseEntity.ok("OTP sent to email. Please verify.");
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<AuthResponse> verifyOtp(@RequestBody OtpRequest request) {
        String token = authService.verifyOtpAndRegister(
                request.getEmail(),
                request.getOtp(),
                request.getUsername(),
                request.getPassword()
        );

        // ✅ Fetch the user details after successful OTP verification
        User user = authService.getUserByUsernameOrEmail(request.getUsername(), request.getEmail());

        return ResponseEntity.ok(new AuthResponse(token, "User registered successfully", user.getUsername(), user.getEmail()));
    }


    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody AuthRequest request) {
        User user = authService.getUserByUsernameOrEmail(request.getUsername(), request.getEmail());
        String token = authService.loginUser(user.getUsername(), user.getEmail(), request.getPassword());

        return ResponseEntity.ok(new AuthResponse(token, "Login successful", user.getUsername(), user.getEmail()));
    }
    @GetMapping("/test/secure")
    public ResponseEntity<String> secure(Authentication authentication) {
        return ResponseEntity.ok("Hello " + authentication.getName());
    }


}
