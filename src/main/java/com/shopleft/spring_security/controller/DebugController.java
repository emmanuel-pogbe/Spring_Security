package com.shopleft.spring_security.controller;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DebugController {

    @GetMapping("/me")
    @ResponseBody
    public Map<String, Object> me(Authentication authentication) {
        // Build a simple JSON snapshot of the current authentication state.
        Map<String, Object> response = new LinkedHashMap<>();

        // Whether Spring Security considers the request authenticated.
        response.put("authenticated", authentication != null && authentication.isAuthenticated());

        // The username/principal name Spring Security currently sees.
        response.put("username", authentication == null ? null : authentication.getName());

        // The concrete principal type tells you whether this came from form login, JWT, or Google OAuth.
        response.put("principalType", authentication == null || authentication.getPrincipal() == null
                ? null
                : authentication.getPrincipal().getClass().getName());

        // Flatten authorities so you can inspect the roles that were actually granted.
        response.put("authorities", authentication == null
                ? java.util.List.of()
                : authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());

        // Add provider-specific details when the principal is an OAuth2 user.
        if (authentication != null && authentication.getPrincipal() instanceof OAuth2User oauth2User) {
            response.put("oauth2Attributes", oauth2User.getAttributes());
        }

        // Add local account details when the principal is a standard UserDetails object.
        if (authentication != null && authentication.getPrincipal() instanceof UserDetails userDetails) {
            response.put("userDetailsUsername", userDetails.getUsername());
        }

        return response;
    }
}