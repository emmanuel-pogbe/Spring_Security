package com.shopleft.spring_security.service;

import com.shopleft.spring_security.dto.SignupBody;
import com.shopleft.spring_security.repository.UserRepository;
import com.shopleft.spring_security.models.Authorities;
import com.shopleft.spring_security.models.User;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    public UserServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }
    @Override
    public String signup(SignupBody signup) {
        User toBeSaved = new User();
        toBeSaved.setUsername(signup.getUsername());

        toBeSaved.setPassword(passwordEncoder.encode(signup.getPassword()));
        toBeSaved.setAuthorities(List.of(new Authorities("USER",toBeSaved)));
        
        Optional<User> doesExist = Optional.ofNullable(userRepository.findByUsername(signup.getUsername()));
        if (doesExist.isPresent()) {
            return "Fail";
        }
        userRepository.save(toBeSaved);
        return "Success";
    }
}
