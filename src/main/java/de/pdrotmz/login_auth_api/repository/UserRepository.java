package de.pdrotmz.login_auth_api.repository;

import de.pdrotmz.login_auth_api.domain.user.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {
}
