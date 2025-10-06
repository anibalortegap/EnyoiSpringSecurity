package co.enyoi.authentication.controller;

import co.enyoi.authentication.model.security.RefreshToken;
import co.enyoi.authentication.repository.RefreshTokenRepository;
import co.enyoi.authentication.service.JwtService;
import co.enyoi.authentication.service.RefreshTokenService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/v1")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtService  jwtService;
    private final RefreshTokenService refreshTokenService;

    public AuthController(AuthenticationManager authenticationManager, JwtService jwtService,
                          RefreshTokenService refreshTokenService) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
    }


    @PostMapping("/auth")
    public Map<String,String> getToken(@RequestBody DtoAuthRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password())
        );


        String jwt = jwtService.generateToken(authentication);

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(request.username());
        return Map.of("accessToken", jwt, "refreshToken", refreshToken.getToken());
    }

    @PostMapping("/refresh")
    public Map<String,String> refreshToken(@RequestBody DtoRefreshToken request) {
        RefreshToken refreshToken = refreshTokenService.findByToken(request.refreshToken)
                .orElseThrow(()-> new RuntimeException("Refresh token not valid"));

        if(refreshTokenService.isRefreshTokenValidExpired(refreshToken)) {
            refreshTokenService.deleteRefreshToken(refreshToken.getUser().getUsername());
            throw new RuntimeException("Refresh token expired");
        }

        String jwt = jwtService.generateToken(new
                UsernamePasswordAuthenticationToken(refreshToken.getUser().getUsername(), null));

        return Map.of("accessToken", jwt);

    }

    record DtoAuthRequest(String username, String password) {}
    record DtoRefreshToken(String refreshToken) {}
}
