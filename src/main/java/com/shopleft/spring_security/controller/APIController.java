package com.shopleft.spring_security.controller;

import com.shopleft.spring_security.config.jwt.JwtUtils;
import com.shopleft.spring_security.dto.AuthenticationRequest;
import com.shopleft.spring_security.dto.SignupBody;
import com.shopleft.spring_security.service.UserService;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1")
public class APIController {
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private final UserService userService;
    APIController(AuthenticationManager authenticationManager, JwtUtils jwtUtils, UserService userService) {
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
        this.userService = userService;
    }
    @GetMapping("/info")
    public String getSecretInfo() {
        return "Shh, this is a secret test for jwts";
    }

    @PostMapping("/passport/auth")
    public ResponseEntity<Map<String,Object>> auth(@RequestBody AuthenticationRequest authenticationRequest) {
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authenticationRequest.getUsername(),
                        authenticationRequest.getPassword()
                )
        );
        UserDetails userDetails = (UserDetails) auth.getPrincipal();
        return ResponseEntity.ok(jwtUtils.generateToken(userDetails.getUsername()));
    }

    @PostMapping("/signup")
    public String signup(@RequestBody SignupBody signupBody) {
        String response = userService.signup(signupBody);
        return response;
    }
}
