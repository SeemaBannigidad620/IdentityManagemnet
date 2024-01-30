package com.aliens.IdentityManagement.service;

import com.aliens.IdentityManagement.entity.User;
import com.aliens.IdentityManagement.repository.UserRepository;
import com.aliens.IdentityManagement.utils.ValidationUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CacheConfig;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;

import java.util.concurrent.TimeUnit;

@Service
@CacheConfig(cacheNames = {"user"})
public class UserService {

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    JwtService jwtService;

    @Autowired
    ValidationUtils validationUtils;

    @Autowired
    RedisTemplate<String, User> redisTemplate;
    public ResponseEntity<String> saveUser(User user) {
        try {
            validationUtils.validateUserDetails(user);
            User cachedUser = redisTemplate.opsForValue().get(userCacheKey(user));
            if (cachedUser != null) {
                throw new RuntimeException("User already exists");
            }
            redisTemplate.opsForValue().set(userCacheKey(user), user, 1, TimeUnit.DAYS);

            User savedUser = userRepository.findByUserNameOrEmail(user.getUserName(), user.getEmail());
            if (!ObjectUtils.isEmpty(savedUser)) {
                throw new RuntimeException("User already exists");
            }
            user.setPassword(passwordEncoder.encode(user.getPassword()));
            userRepository.save(user);
            return ResponseEntity.status(HttpStatus.CREATED).body("User added to the server");
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    public static String userCacheKey(User user) {
        return "user:" + user.getUserName() + user.getEmail(); // You can customize this key as needed
    }

    public String generateToken(String userName) {
        return jwtService.generateToken(userName);
    }

    public boolean validateToken(String token) {
        return jwtService.validateToken(token);
    }

}
