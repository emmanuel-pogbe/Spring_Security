package com.shopleft.spring_security.repository;

import com.shopleft.spring_security.models.User;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    @EntityGraph(attributePaths = "authorities")
    public User findByUsername(String username);

    @EntityGraph(attributePaths = "authorities")
    public User findByOauth2ProviderAndOauth2Subject(String oauth2Provider, String oauth2Subject);
}
