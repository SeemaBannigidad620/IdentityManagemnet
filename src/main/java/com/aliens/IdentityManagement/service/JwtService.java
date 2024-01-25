package com.aliens.IdentityManagement.service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.springframework.stereotype.Service;
import org.slf4j.LoggerFactory;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtService {

    private static final Logger logger = LoggerFactory.getLogger(JwtService.class);

    public static final String SECRET = "5367566B59703373367639792F423F4528482B4D6251655468576D5A71347437";

    public boolean validateToken(String authToken) {
        try {
            Jwts.parserBuilder().setSigningKey(getSignKey()).build().parse(authToken);
            return true;
        } catch (MalformedJwtException e) {
            logger.info(("Invalid JWT token: {}"), e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error(("JWT token is expired: {}"), e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error(("JWT token is unsupported: {}"), e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error(("JWT claims string is empty: {}"), e.getMessage());
        } catch (Exception e){
            logger.error(("Invalid token: {}"), e.getMessage());
        }

        return false;
    }


    public String generateToken(String userName) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userName);
    }

    private String createToken(Map<String, Object> claims, String userName) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userName)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 30))
                .signWith(getSignKey(), SignatureAlgorithm.HS256).compact();
    }

    private Key getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
