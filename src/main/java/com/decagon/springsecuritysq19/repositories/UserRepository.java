package com.decagon.springsecuritysq19.repositories;

import com.decagon.springsecuritysq19.model.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;

public interface UserRepository extends JpaRepository<Users, Long> {

    Optional<UserDetails> findByUsername(String username);
}
