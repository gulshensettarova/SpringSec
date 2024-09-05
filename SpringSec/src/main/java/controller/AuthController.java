package controller;

import dto.request.SignInRequest;
import dto.response.JwtAuthenticationResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import service.AuthenticationService;
import security.UserPrincipal;
import security.jwt.JwtProvider;

import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationService authenticationService;
    private final JwtProvider jwtProvider;

    public AuthController(AuthenticationService authenticationService, JwtProvider jwtProvider) {
        this.authenticationService = authenticationService;
        this.jwtProvider = jwtProvider;
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@RequestBody SignInRequest signInRequest) {
        // İstifadəçinin məlumatlarını yoxlayıb JWT tokenlərini yaradın
        String accessToken = authenticationService.singInAndReturnJWT(signInRequest);
        String refreshToken = jwtProvider.generateRefreshToken((UserPrincipal) authenticationService.getUserPrincipal(signInRequest.getUsername()));

        // Refresh token-i cookie-də saxlayın
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.SET_COOKIE, createCookie("refreshToken", refreshToken));

        // JWT access token və refresh token-i qaytarın
        return ResponseEntity.ok()
                .headers(headers)
                .body(new JwtAuthenticationResponse(accessToken));
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(HttpServletRequest request) {
        // Refresh token-i əldə edirik
        String refreshToken = extractRefreshToken(request);

        // Token-i yeniləyirik
        String newAccessToken = jwtProvider.refreshToken(refreshToken);

        return ResponseEntity.ok(new JwtAuthenticationResponse(newAccessToken));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser(HttpServletRequest request) {
        // Refresh token-i əldə edirik
        String refreshToken = extractRefreshToken(request);

        // Token-i qara siyahıya alırıq
        jwtProvider.blacklistToken(refreshToken);

        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    private String extractRefreshToken(HttpServletRequest request) {
        return request.getHeader(HttpHeaders.COOKIE).split("=")[1];
    }

    private String createCookie(String name, String value) {
        return String.format("%s=%s; HttpOnly; Path=/; Max-Age=%d", name, value, jwtProvider.getJWT_REFRESH_EXPIRATION_IN_MS()/1000);
    }
}
