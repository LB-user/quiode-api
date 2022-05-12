package com.quiode.repositories;

import java.util.Optional;
import org.springframework.data.mongodb.repository.MongoRepository;
import com.quiode.models.ERole;
import com.quiode.models.Role;
public interface RoleRepository extends MongoRepository<Role, String> {
    Optional<Role> findByName(ERole name);
}
