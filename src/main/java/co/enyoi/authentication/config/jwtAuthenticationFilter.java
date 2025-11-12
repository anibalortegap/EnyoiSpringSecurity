package co.enyoi.authentication.config;

import co.enyoi.authentication.service.JpaUserDetailsService;
import co.enyoi.authentication.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class jwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(jwtAuthenticationFilter.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtService jwtService;
    private final JpaUserDetailsService userDetailsService;

    public jwtAuthenticationFilter(JwtService jwtService, JpaUserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        // Skip JWT processing for CORS preflight requests
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            logger.debug("Skipping JWT authentication for CORS preflight OPTIONS request: {}", request.getRequestURI());
            filterChain.doFilter(request, response);
            return;
        }

        // Skip JWT processing for public endpoints
        if (isPublicEndpoint(request)) {
            logger.debug("Skipping JWT authentication for public endpoint: {}", request.getRequestURI());
            filterChain.doFilter(request, response);
            return;
        }

        try {
            String jwt = extractJwtFromRequest(request);

            if (jwt != null && StringUtils.hasText(jwt)) {
                authenticateUser(jwt, request);
            }

        } catch (Exception ex) {
            logger.error("Cannot set user authentication: {}", ex.getMessage());
            // Continue with the filter chain even if authentication fails
            // The security configuration will handle unauthorized access
        }

        filterChain.doFilter(request, response);
    }

    private boolean isPublicEndpoint(HttpServletRequest request) {
        String uri = request.getRequestURI();

        // List of public endpoints that don't require JWT authentication
        return uri.equals("/api/v1/auth") ||
               uri.startsWith("/api/v1/auth/") ||
               uri.equals("/api/v1/refresh") ||
               uri.startsWith("/api/v1/refresh/") ||
               uri.startsWith("/api/v1/gateway/auth/") ||
               uri.equals("/api/v1") ||
               uri.startsWith("/h2-console/");
    }

    private String extractJwtFromRequest(HttpServletRequest request) {
        String authorizationHeader = request.getHeader(AUTHORIZATION_HEADER);

        // Check if header exists and has content
        if (!StringUtils.hasText(authorizationHeader)) {
            logger.debug("No Authorization header found for request: {}", request.getRequestURI());
            return null;
        }

        // Check if header starts with Bearer prefix
        if (!authorizationHeader.startsWith(BEARER_PREFIX)) {
            logger.debug("Authorization header does not start with Bearer prefix for request: {}", request.getRequestURI());
            return null;
        }

        // Extract token
        String token = authorizationHeader.substring(BEARER_PREFIX.length());

        if (!StringUtils.hasText(token)) {
            logger.debug("Empty JWT token after Bearer prefix for request: {}", request.getRequestURI());
            return null;
        }

        return token;
    }

    private void authenticateUser(String jwt, HttpServletRequest request) {
        try {
            String username = jwtService.extractUsername(jwt);

            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                if (jwtService.isTokenValid(jwt, userDetails.getUsername())) {
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );

                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authentication);

                    logger.debug("User '{}' authenticated successfully for request: {}", username, request.getRequestURI());
                } else {
                    logger.debug("Invalid JWT token for user: {}", username);
                }
            }
        } catch (Exception ex) {
            logger.error("Error authenticating user: {}", ex.getMessage());
            throw ex;
        }
    }
}
