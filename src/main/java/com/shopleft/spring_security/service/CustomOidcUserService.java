package com.shopleft.spring_security.service;

import java.util.LinkedHashSet;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import com.shopleft.spring_security.models.User;
import com.shopleft.spring_security.repository.UserRepository;

@Service
public class CustomOidcUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    // Delegate provided by Spring to fetch OIDC user details from Google.
    private final OidcUserService delegate = new OidcUserService();
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public CustomOidcUserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = delegate.loadUser(userRequest);

        String provider = userRequest.getClientRegistration().getRegistrationId();
        String subject = oidcUser.getSubject();
        String email = stringAttr(oidcUser, "email");
        String displayName = stringAttr(oidcUser, "name");
        String pictureUrl = stringAttr(oidcUser, "picture");
        String username = (email != null && !email.isBlank()) ? email : provider + "_" + subject;

        User appUser = userRepository.findByOauth2ProviderAndOauth2Subject(provider, subject);
        if (appUser == null) {
            appUser = userRepository.findByUsername(username);
        }

        if (appUser == null) {
            appUser = new User();
            appUser.setUsername(username);
            appUser.setPassword(passwordEncoder.encode("OIDC_USER_PLACEHOLDER"));
            appUser.setOauth2Provider(provider);
            appUser.setOauth2Subject(subject);
            appUser.setEmail(email);
            appUser.setDisplayName(displayName);
            appUser.setPictureUrl(pictureUrl);
            appUser.addAuthority("ROLE_USER");
        } else {
            appUser.setOauth2Provider(provider);
            appUser.setOauth2Subject(subject);
            appUser.setEmail(email);
            appUser.setDisplayName(displayName);
            appUser.setPictureUrl(pictureUrl);

            boolean hasUserRole = appUser.getAuthorities().stream()
                    .anyMatch(a -> "ROLE_USER".equalsIgnoreCase(a.getAuthority()));
            if (!hasUserRole) {
                appUser.addAuthority("ROLE_USER");
            }

            if (appUser.getPassword() == null || appUser.getPassword().isBlank()) {
                appUser.setPassword(passwordEncoder.encode("OIDC_USER_PLACEHOLDER"));
            }
        }

        userRepository.save(appUser);

        // Merge provider authorities with app role so hasRole("USER") passes immediately.
        Set<GrantedAuthority> mergedAuthorities = new LinkedHashSet<>(oidcUser.getAuthorities());
        mergedAuthorities.add(new SimpleGrantedAuthority("ROLE_USER"));

        return new DefaultOidcUser(mergedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo(), "sub");
    }

    private String stringAttr(OidcUser user, String key) {
        Object value = user.getAttributes().get(key);
        return value == null ? null : value.toString();
    }
}