package org.example.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secretKey;

    public String generateToken(String username) {

        return Jwts.builder()
                .setSubject(username)
                .claim("roles", List.of("ADMIN"))
                .claim("email", username + "@gmail.com")
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    private java.security.Key getSignInKey() {
        byte[] keyBytes = secretKey.getBytes();
        return new javax.crypto.spec.SecretKeySpec(keyBytes, SignatureAlgorithm.HS256.getJcaName());
    }
}

