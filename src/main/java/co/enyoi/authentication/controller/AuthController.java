package co.enyoi.authentication.controller;

import co.enyoi.authentication.dto.AuthRequest;
import co.enyoi.authentication.dto.AuthResponse;
import co.enyoi.authentication.dto.RefreshTokenRequest;
import co.enyoi.authentication.exception.AuthenticationFailedException;
import co.enyoi.authentication.exception.RefreshTokenExpiredException;
import co.enyoi.authentication.exception.RefreshTokenNotFoundException;
import co.enyoi.authentication.model.security.RefreshToken;
import co.enyoi.authentication.service.JwtService;
import co.enyoi.authentication.service.RefreshTokenService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    public AuthController(AuthenticationManager authenticationManager, JwtService jwtService,
                          RefreshTokenService refreshTokenService) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
    }


    @PostMapping("/auth")
    public ResponseEntity<AuthResponse> authenticate(@Valid @RequestBody AuthRequest request) {
        try {
            logger.info("Authentication attempt for user: {}", request.username());

            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.username(), request.password())
            );

            String jwt = jwtService.generateToken(authentication);
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(request.username());

            AuthResponse response = new AuthResponse(
                    jwt,
                    refreshToken.getToken(),
                    jwtService.getExpirationTime()
            );

            logger.info("Authentication successful for user: {}", request.username());
            return ResponseEntity.ok(response);

        } catch (AuthenticationException ex) {
            logger.error("Authentication failed for user: {}", request.username());
            throw new AuthenticationFailedException("Invalid username or password");
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        logger.info("Refresh token request received");

        RefreshToken refreshToken = refreshTokenService.findByToken(request.refreshToken())
                .orElseThrow(() -> new RefreshTokenNotFoundException(request.refreshToken()));

        if (refreshTokenService.isRefreshTokenValidExpired(refreshToken)) {
            String username = refreshToken.getUser().getUsername();
            refreshTokenService.deleteRefreshToken(username);
            throw new RefreshTokenExpiredException(request.refreshToken(), refreshToken.getExpiryDate());
        }

        String jwt = jwtService.generateToken(new
                UsernamePasswordAuthenticationToken(refreshToken.getUser().getUsername(), null));

        AuthResponse response = new AuthResponse(
                jwt,
                null,
                jwtService.getExpirationTime()
        );

        logger.info("Token refreshed successfully for user: {}", refreshToken.getUser().getUsername());
        return ResponseEntity.ok(response);
    }
}
