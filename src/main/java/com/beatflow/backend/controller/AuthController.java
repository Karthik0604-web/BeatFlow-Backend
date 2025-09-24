package com.beatflow.backend.controller;

import com.beatflow.backend.dto.AuthResponse;
import com.beatflow.backend.dto.LoginRequest;
import com.beatflow.backend.dto.SignUpRequest;
import com.beatflow.backend.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    
    private final AuthService authService;
    
    public AuthController(AuthService authService) {
        this.authService = authService;
    }
    
    /**
     * Endpoint for user registration.
     * @param request The signup request containing name, email, and password.
     * @return A response entity indicating success or failure.
     */
    @PostMapping("/register")
    public ResponseEntity<String> signup(@RequestBody SignUpRequest request) {
        try {
            authService.signup(request);
            return ResponseEntity.ok("User registered successfully");
        } catch (IllegalArgumentException e) {
            // Catches the "Email already in use" error from the service
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
    
    /**
     * Endpoint for user authentication.
     * @param request The login request containing email and password.
     * @return A response entity containing the JWT.
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest request) {
        // The service handles the complex password checking logic.
        return ResponseEntity.ok(authService.login(request));
    }
}
}
