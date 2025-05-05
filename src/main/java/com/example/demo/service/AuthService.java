package com.example.demo.service;

import com.example.demo.model.Role;
import com.example.demo.model.User;
import com.example.demo.model.Otp;
import com.example.demo.repository.UserRepository;
import com.example.demo.repository.OtpRepository;
import com.example.demo.security.JwtTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Optional;
import java.util.Random;

@Service
@RequiredArgsConstructor
public class AuthService {

    private static final String USERNAME_EXISTS = "Username already exists";
    private static final String INVALID_OR_EXPIRED_OTP = "Invalid or expired OTP";
    private static final String INVALID_CREDENTIALS = "Invalid credentials";
    private static final String USER_NOT_FOUND = "User not found";

    private final UserRepository userRepository;
    private final OtpRepository otpRepository;
    private final EmailService emailService;
    private final PasswordEncoder passwordEncoder;  // Updated to use PasswordEncoder
    private final JwtTokenService jwtTokenService;

    /**
     * Initiates the signup process by generating and sending an OTP to the user's email.
     *
     * @param username The desired username
     * @param email    The user's email
     * @param password The desired password
     */
    public void initiateSignup(String username, String email, String password) {
        if (userRepository.findByUsername(username).isPresent()) {
            throw new RuntimeException(USERNAME_EXISTS);
        }

        String otpCode = generateOtp();
        otpRepository.save(new Otp(email, otpCode));

        emailService.sendOtpEmail(email, otpCode);
    }

    /**
     * Verifies the OTP and completes user registration.
     *
     * @param email    The user's email
     * @param otpCode  The OTP code received by the user
     * @param username The desired username
     * @param password The desired password
     * @return A success message after registration
     */
    public String verifyOtpAndRegister(String email, String otpCode, String username, String password) {
        // Retrieve the OTP from the database
        Optional<Otp> storedOtp = otpRepository.findByEmail(email);

        // Check if OTP exists and is valid
        if (storedOtp.isEmpty() || !storedOtp.get().getOtp().equals(otpCode)) {
            throw new RuntimeException(INVALID_OR_EXPIRED_OTP);
        }

        // Proceed with user registration
        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        user.setRole(Role.USER);

        userRepository.save(user);

        // Delete the OTP after successful registration
        otpRepository.delete(storedOtp.get());

        // Generate JWT token after successful registration
        UserDetails userDetails = new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                Collections.emptyList()
        );

        // Generate JWT token and return it
        String token = jwtTokenService.generateToken(userDetails, user.getId().toString(), user.getEmail());

        return token;  // Return the generated token
    }



    /**
     * Authenticates a user and returns a JWT token if successful.
     *
     * @param username The username
     * @param email    The email (optional, not currently used in logic)
     * @param password The password
     * @return The generated JWT token
     */
    public String loginUser(String username, String email, String password) {
        Optional<User> userOptional = userRepository.findByUsername(username);
        if (userOptional.isPresent() && passwordEncoder.matches(password, userOptional.get().getPassword())) {
            User user = userOptional.get();

            // Create Spring Security UserDetails
            UserDetails userDetails = new org.springframework.security.core.userdetails.User(
                    user.getUsername(),
                    user.getPassword(),
                    Collections.emptyList()
            );

            // Generate JWT token
            return jwtTokenService.generateToken(userDetails, user.getId().toString(), user.getEmail());
        }

        throw new RuntimeException(INVALID_CREDENTIALS);
    }

    /**
     * Retrieves a user by either username or email.
     *
     * @param username The username
     * @param email    The email
     * @return The User object
     */
    public User getUserByUsernameOrEmail(String username, String email) {
        return userRepository.findByUsername(username)
                .or(() -> userRepository.findByEmail(email))
                .orElseThrow(() -> new RuntimeException(USER_NOT_FOUND));
    }

    /**
     * Generates a 6-digit OTP.
     *
     * @return The generated OTP as a String
     */
    private String generateOtp() {
        return String.valueOf(100000 + new Random().nextInt(900000));
    }
}
