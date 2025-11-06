package co.enyoi.authentication.service;

import co.enyoi.authentication.exception.InvalidJwtTokenException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.stream.Collectors;

@Service
public class JwtService {

    private static final Logger logger = LoggerFactory.getLogger(JwtService.class);

    private final SecretKey secretKey;
    private final long expirationTime;


    public JwtService(@Value("${jwt.secret-key}") String secretKey, @Value("${jwt.expiration}") long expirationTime) {
        this.secretKey = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
        this.expirationTime = expirationTime;
    }

    //Method generate JWT - Authentication Success
    public String generateToken(Authentication authentication) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationTime);

        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        logger.debug("Generating JWT token for user: {}", authentication.getName());

        return Jwts.builder()
                .subject(authentication.getName())
                .claim("auth", authorities)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(secretKey)
                .compact();
    }

    public Claims extractAllClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException ex) {
            logger.warn("JWT token is expired");
            throw ex;
        } catch (JwtException ex) {
            logger.error("JWT token validation failed: {}", ex.getMessage());
            throw new InvalidJwtTokenException("Invalid JWT token", ex);
        }
    }

    public String extractUsername(String token) {
        try {
            return extractAllClaims(token).getSubject();
        } catch (Exception ex) {
            logger.error("Failed to extract username from token: {}", ex.getMessage());
            throw new InvalidJwtTokenException("Failed to extract username from token", ex);
        }
    }

    public boolean isTokenExpired(String token) {
        try {
            return extractAllClaims(token).getExpiration().before(new Date());
        } catch (ExpiredJwtException ex) {
            return true;
        }
    }

    public boolean isTokenValid(String token, String username) {
        try {
            final String tokenUsername = extractUsername(token);
            boolean isValid = tokenUsername.equals(username) && !isTokenExpired(token);

            if (!isValid) {
                logger.warn("Token validation failed for user: {}", username);
            }

            return isValid;
        } catch (Exception ex) {
            logger.error("Error validating token: {}", ex.getMessage());
            return false;
        }
    }

    public long getExpirationTime() {
        return expirationTime;
    }

}
