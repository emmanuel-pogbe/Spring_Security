package com.shopleft.spring_security.service;

import com.shopleft.spring_security.dto.SignupBody;

public interface UserService {
    public String signup(SignupBody signup);
    
}
