package co.enyoi.authentication.service;

import co.enyoi.authentication.dto.CreateUserRequest;
import co.enyoi.authentication.dto.UserResponse;
import co.enyoi.authentication.exception.RoleNotFoundException;
import co.enyoi.authentication.exception.UserAlreadyExistsException;
import co.enyoi.authentication.model.Role;
import co.enyoi.authentication.model.User;
import co.enyoi.authentication.repository.RoleRepository;
import co.enyoi.authentication.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository,
                      RoleRepository roleRepository,
                      PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public UserResponse createUser(CreateUserRequest request) {
        logger.info("Creating new user: {}", request.username());

        // Validate username doesn't exist
        if (userRepository.findByUsername(request.username()).isPresent()) {
            logger.warn("Attempt to create user with existing username: {}", request.username());
            throw new UserAlreadyExistsException(request.username());
        }

        // Validate and fetch roles
        Set<Role> roles = new HashSet<>();
        for (String roleName : request.roles()) {
            Role role = roleRepository.findByName(roleName)
                    .orElseThrow(() -> {
                        logger.error("Role not found: {}", roleName);
                        return new RoleNotFoundException(roleName);
                    });
            roles.add(role);
        }

        // Create user
        User user = new User();
        user.setUsername(request.username());
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setRoles(roles);

        User savedUser = userRepository.save(user);
        logger.info("User created successfully: {} with ID: {}", savedUser.getUsername(), savedUser.getId());

        // Build response
        Set<String> roleNames = savedUser.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toSet());

        return new UserResponse(
                savedUser.getId(),
                savedUser.getUsername(),
                roleNames
        );
    }
}
