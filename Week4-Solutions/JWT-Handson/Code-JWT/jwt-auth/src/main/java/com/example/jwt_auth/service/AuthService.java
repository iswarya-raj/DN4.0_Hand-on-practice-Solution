package com.example.jwt_auth.service;

import com.example.jwt_auth.security.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Service
public class AuthService {

    @Autowired
    private CustomUserDetailsService userDetailsService;
    
    public String authenticate(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Basic ")) {
            String base64Credentials = authHeader.substring("Basic ".length());
            byte[] credDecoded = Base64.getDecoder().decode(base64Credentials);
            String credentials = new String(credDecoded, StandardCharsets.UTF_8);
            final String[] values = credentials.split(":", 2);
            
            if (values.length == 2) {
                String username = values[0];
                String password = values[1];
                
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                if (userDetails != null && userDetails.getPassword().equals(password)) {
                    return username;
                }
            }
        }
        throw new RuntimeException("Invalid credentials");
    }
    
    public UserDetails loadUserByUsername(String username) {
        return userDetailsService.loadUserByUsername(username);
    }
}