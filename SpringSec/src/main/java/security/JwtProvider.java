package security;


import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtProvider {
    // 'application.yml' faylından JWT tokeninin etibarlılıq müddətini milisaniyə şəklində yükləyir.
    @Value("${authentication.jwt.jwt-token-validity-ms}")
    private Long jwtTokenValidityInMs;

    // 'application.yml' faylından JWT üçün istifadə olunan özəl açarı (private key) yükləyir.
    @Value("${authentication.jwt.private-key}")
    private String JWT_PRIVATE_KEY;

    // 'application.yml' faylından JWT üçün istifadə olunan açıq açarı (public key) yükləyir.
    @Value("${authentication.jwt.public-key}")
    private String JWT_PUBLIC_KEY;

    // İstifadəçi məlumatlarına əsaslanaraq JWT tokenini yaradır.
    public String generateToken(UserDetails userDetails) {
        // Tokeni yaratmaq üçün Jwts.builder() metodundan istifadə olunur.
        return Jwts.builder()
                // Token sahibini təyin edir (bu adətən istifadəçi adı olur).
                .setSubject(userDetails.getUsername())
                // Tokenin yaradılma tarixini təyin edir.
                .setIssuedAt(new Date())
                // Tokenin etibarlılıq müddətini təyin edir.
                .setExpiration(new Date(new Date().getTime() + jwtTokenValidityInMs))
                // Tokeni özəl açarla (private key) imzalayır.
                .signWith(SignatureAlgorithm.RS256, JWT_PRIVATE_KEY)
                // Tokeni string olaraq qaytarır.
                .compact();
    }

    // Verilmiş JWT tokeninin düzgün olub-olmadığını yoxlayır.
    public boolean validateToken(String token) {
        try {
            // Tokeni doğrulamaq üçün parserdən istifadə edir.
            Jwts.parser()
                    // Tokenin imzasını açıq açarla (public key) doğrulayır.
                    .setSigningKey(JWT_PUBLIC_KEY)
                    // Tokeni parse edir.
                    .parseClaimsJws(token);
            // Əgər token düzgündürsə, true qaytarır.
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            // Token düzgün olmadıqda, false qaytarır.
            return false;
        }
    }

    // Verilmiş JWT tokenindən istifadəçi adını (subject) oxuyur.
    public String getUsernameFromToken(String token) {
        // Tokeni parse etmək üçün parserdən istifadə edir.
        return Jwts.parser()
                // Tokenin imzasını açıq açarla (public key) doğrulayır.
                .setSigningKey(JWT_PUBLIC_KEY)
                // Tokeni parse edir və içərisindən subject-i (istifadəçi adı) qaytarır.
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }
}
