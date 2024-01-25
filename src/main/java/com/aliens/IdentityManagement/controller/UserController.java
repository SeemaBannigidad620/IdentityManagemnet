package com.aliens.IdentityManagement.controller;

import com.aliens.IdentityManagement.entity.ResponseBody;
import com.aliens.IdentityManagement.entity.User;
import com.aliens.IdentityManagement.exception.InvalidUserDataException;
import com.aliens.IdentityManagement.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/identity")
public class UserController {

    @Autowired
    UserService userService;

    @Autowired
    AuthenticationManager authenticationManager;

    @PostMapping("/create/user")
    public ResponseEntity<String> createUser(@RequestBody User user) {
        try {
            userService.saveUser(user);
            return ResponseEntity.status(HttpStatus.CREATED).body("User added to the server");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(e.getMessage());
        }
    }

    @GetMapping("/get/token")
    public ResponseEntity<String> getToken(@RequestBody User user) {
        try {
            Authentication authenticate = authenticationManager.authenticate(new
                    UsernamePasswordAuthenticationToken(user.getUserName(), user.getPassword()));
            if (authenticate.isAuthenticated()) {
                return ResponseEntity.status(HttpStatus.OK).body(userService.generateToken(user.getUserName()));
            } else {
                throw new InvalidUserDataException(HttpStatus.UNAUTHORIZED, "Bad Credentials");
            }
        }catch (Exception e){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        }
    }

    @GetMapping("/validate/token")
    public ResponseEntity<ResponseBody> validateToken(@RequestHeader("Authorization") String token) {

        boolean isTokenValid = userService.validateToken(token);

        HttpStatus status = isTokenValid ? HttpStatus.OK : HttpStatus.UNAUTHORIZED;
        String body = isTokenValid ? "valid token" : "invalid token";

        ResponseBody responseBody = new ResponseBody(status, body);

        return new ResponseEntity<>(responseBody, status);
    }

}

