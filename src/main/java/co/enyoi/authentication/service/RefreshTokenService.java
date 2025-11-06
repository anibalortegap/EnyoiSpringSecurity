package co.enyoi.authentication.service;

import co.enyoi.authentication.exception.UserNotFoundException;
import co.enyoi.authentication.model.User;
import co.enyoi.authentication.model.security.RefreshToken;
import co.enyoi.authentication.repository.RefreshTokenRepository;
import co.enyoi.authentication.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private static final Logger logger = LoggerFactory.getLogger(RefreshTokenService.class);

    @Value("${jwt.refresh-toke.expiration-ms:604800000}")
    private Long refreshTokenDurationMs;


    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository, UserRepository userRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository =  userRepository;
    }

    @Transactional
    public RefreshToken createRefreshToken(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException(username));

        logger.info("Creating refresh token for user: {}", username);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
        refreshToken.setToken(UUID.randomUUID().toString());

        return refreshTokenRepository.save(refreshToken);
    }

    public Optional<RefreshToken> findByToken(String token) {
        logger.debug("Finding refresh token");
        return refreshTokenRepository.findByToken(token);
    }

    public boolean isRefreshTokenValidExpired(RefreshToken token) {
        boolean isExpired = token.getExpiryDate().isBefore(Instant.now());
        if (isExpired) {
            logger.warn("Refresh token expired for user: {}", token.getUser().getUsername());
        }
        return isExpired;
    }

    @Transactional
    public void deleteRefreshToken(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException(username));

        logger.info("Deleting refresh token for user: {}", username);
        refreshTokenRepository.deleteByUser(user);
    }
}
