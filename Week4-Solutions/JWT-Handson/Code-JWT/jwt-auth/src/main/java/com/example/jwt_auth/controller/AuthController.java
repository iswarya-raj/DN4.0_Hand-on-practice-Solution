package com.example.jwt_auth.controller;

import com.example.jwt_auth.dto.JwtResponse;
import com.example.jwt_auth.security.JwtTokenUtil;
import com.example.jwt_auth.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    @Autowired
    private JwtTokenUtil jwtTokenUtil;
    
    @Autowired
    private AuthService authService;

    @PostMapping("/authenticate")
    public ResponseEntity<JwtResponse> createAuthenticationToken(
            @RequestHeader("Authorization") String authHeader) {
        
        String username = authService.authenticate(authHeader);
        final UserDetails userDetails = authService.loadUserByUsername(username);
        final String token = jwtTokenUtil.generateToken(userDetails);
        
        return ResponseEntity.ok(new JwtResponse(token));
    }
}