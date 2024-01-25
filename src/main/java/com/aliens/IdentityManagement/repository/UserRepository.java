package com.aliens.IdentityManagement.repository;

import com.aliens.IdentityManagement.entity.User;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface UserRepository extends MongoRepository<User, Integer> {
    User findByUserNameOrEmail(String userName, String email);

    Optional<User> findByUserName(String username);

    User findByUserNameAndEmail(String userName, String email);
}
