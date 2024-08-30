package model.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import model.entity.Role;
public interface RoleRepository extends JpaRepository<Role, Long> {
}
