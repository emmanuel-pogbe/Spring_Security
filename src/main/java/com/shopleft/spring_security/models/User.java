package com.shopleft.spring_security.models;

import jakarta.persistence.*;

import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "user_table")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Local username used by form login and as fallback identity for OAuth users.
    private String username;

    // BCrypt password for local users (OAuth users get a random unusable value).
    private String password;

    // OAuth provider id, e.g. google.
    private String oauth2Provider;

    // Stable provider subject/id from OAuth provider response.
    private String oauth2Subject;

    // Email from OAuth provider payload.
    private String email;

    // Display name from OAuth provider payload.
    private String displayName;

    // Avatar/image URL from OAuth provider payload.
    private String pictureUrl;

    public User() {}

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Authorities> authorities = new ArrayList<>();

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getOauth2Provider() {
        return oauth2Provider;
    }

    public void setOauth2Provider(String oauth2Provider) {
        this.oauth2Provider = oauth2Provider;
    }

    public String getOauth2Subject() {
        return oauth2Subject;
    }

    public void setOauth2Subject(String oauth2Subject) {
        this.oauth2Subject = oauth2Subject;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public String getPictureUrl() {
        return pictureUrl;
    }

    public void setPictureUrl(String pictureUrl) {
        this.pictureUrl = pictureUrl;
    }

    public List<Authorities> getAuthorities() {
        return authorities;
    }

    public void setAuthorities(List<Authorities> authorities) {
        this.authorities = authorities;
    }

    public void addAuthority(String authority) {
        // Keeps both sides of the relation in sync before JPA flushes changes.
        Authorities userAuthority = new Authorities();
        userAuthority.setAuthority(authority);
        userAuthority.setUser(this);
        this.authorities.add(userAuthority);
    }
}
