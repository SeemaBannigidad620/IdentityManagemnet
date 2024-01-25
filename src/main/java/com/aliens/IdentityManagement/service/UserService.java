package com.aliens.IdentityManagement.service;

import com.aliens.IdentityManagement.entity.User;
import com.aliens.IdentityManagement.repository.UserRepository;
import com.aliens.IdentityManagement.utils.ValidationUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;

@Service
public class UserService {

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    JwtService jwtService;

    @Autowired
    ValidationUtils validationUtils;

    public ResponseEntity<String> saveUser(User user) {
        try {
            validationUtils.validateUserDetails(user);
            User savedUser = userRepository.findByUserNameOrEmail(user.getUserName(), user.getEmail());
            if (!ObjectUtils.isEmpty(savedUser)) {
                throw new RuntimeException("User already exists");
            }
            user.setPassword(passwordEncoder.encode(user.getPassword()));
            userRepository.save(user);
            return ResponseEntity.status(HttpStatus.CREATED).body("User added to the server");
        }catch (Exception e){
            throw new RuntimeException(e.getMessage());
        }
    }

    public String generateToken(String userName) {
        return jwtService.generateToken(userName);
    }

    public boolean validateToken(String token) {
        return jwtService.validateToken(token);
    }

}
