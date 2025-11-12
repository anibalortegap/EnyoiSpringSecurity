package co.enyoi.authentication.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * CORS configuration to allow cross-origin requests from the frontend application.
 * <p>
 * This configuration enables the frontend hosted at Lovable preview domain to make
 * requests to the API endpoints, including preflight OPTIONS requests.
 */
@Configuration
public class CorsConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
                .allowedOrigins(
                        "https://id-preview--484f6468-e188-4e2e-9efc-c3e1903e7299.lovable.app",
                        "http://localhost:3000",
                        "http://localhost:5173"
                )
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH")
                .allowedHeaders("*")
                .exposedHeaders("X-Request-Id", "Authorization")
                .allowCredentials(true)
                .maxAge(3600);
    }
}
