package model.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import model.entity.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {
    Optional<User> findByUsername(String username);

}
