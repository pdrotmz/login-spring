package de.pdrotmz.login_auth_api.controller;

import de.pdrotmz.login_auth_api.domain.user.User;
import de.pdrotmz.login_auth_api.dto.LoginRequestDTO;
import de.pdrotmz.login_auth_api.dto.RegisterRequestDTO;
import de.pdrotmz.login_auth_api.dto.ResponseDTO;
import de.pdrotmz.login_auth_api.infra.security.TokenService;
import de.pdrotmz.login_auth_api.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody LoginRequestDTO loginRequestDTO) {
        User user = this.userRepository.findByEmail(loginRequestDTO.email()).orElseThrow(() -> new RuntimeException("User Not Found"));
        if(passwordEncoder.matches(loginRequestDTO.password(), user.getPassword())) {
            String token = this.tokenService.generateToken(user);
            return ResponseEntity.ok(new ResponseDTO(user.getName(), token));
        }
        return ResponseEntity.badRequest().build();
    }

    @PostMapping("/register")
    public ResponseEntity login(@RequestBody RegisterRequestDTO registerRequestDTO) {
        Optional<User> user = this.userRepository.findByEmail(registerRequestDTO.email());

        if(user.isEmpty()) {
            User newUser = new User();
            newUser.setPassword(passwordEncoder.encode(registerRequestDTO.password()));
            newUser.setEmail(registerRequestDTO.email());
            newUser.setName(registerRequestDTO.name());
            this.userRepository.save(newUser);

            String token = this.tokenService.generateToken(newUser);
            return ResponseEntity.ok(new ResponseDTO(newUser.getName(), token));
        }
        return ResponseEntity.badRequest().build();
    }
}
