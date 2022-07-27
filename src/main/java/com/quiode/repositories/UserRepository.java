package com.quiode.repositories;

import java.util.Optional;

import com.quiode.models.User;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface UserRepository extends MongoRepository<User, String> {
    User findByUsername(String username);
    User findByEmail(String email);
    User findByResetToken(String token);
    Boolean existsByUsername(String username);
    Boolean existsByEmail(String email);
}
