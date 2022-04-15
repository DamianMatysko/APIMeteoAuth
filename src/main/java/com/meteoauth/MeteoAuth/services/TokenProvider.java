package com.meteoauth.MeteoAuth.services;

import com.meteoauth.MeteoAuth.entities.Station;
import com.meteoauth.MeteoAuth.oAuth2.AppProperties;
import com.meteoauth.MeteoAuth.oAuth2.LocalUser;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class TokenProvider {

    private static final Logger logger = LoggerFactory.getLogger(TokenProvider.class);

    final private AppProperties appProperties;

    public TokenProvider(AppProperties appProperties) {
        this.appProperties = appProperties;
    }

    public String createToken(Authentication authentication) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + appProperties.getAuth().getTokenExpirationMsec());

        Map<String, Object> claims = new HashMap<>();
        claims.put("authorities", "USER_ROLE");

        String subject = ((LocalUser) authentication.getPrincipal()).getUser().getEmail();
        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS256, appProperties.getAuth().getTokenSecret()).compact();
    }

    public Long getUserIdFromToken(String token) {
        Claims claims = Jwts.parser().setSigningKey(appProperties.getAuth().getTokenSecret()).parseClaimsJws(token).getBody();
        return Long.parseLong(claims.getSubject());
    }

    public String extractSubject(String token) {
        if (token.startsWith("Bearer ")) {
            token = token.substring(7);
        }
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(appProperties.getAuth().getTokenSecret()).parseClaimsJws(token).getBody();
    }

    public boolean hasRole(String token, String role) {
        final Claims claims = extractAllClaims(token);
        Object authorities = claims.get("authorities");
        return authorities.toString().contains(role);
    }

    public Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("authorities", "USER_ROLE");
        return createToken(claims, userDetails.getUsername());
    }

    public String generateRefreshToken(UserDetails userDetails) {
        return createRefreshToken(userDetails.getUsername());
    }

    public String generateTokenForStation(Station station) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("authorities", "STATION_ROLE");
        return createStationToken(claims, station.getId().toString());

    }

    private String createToken(Map<String, Object> claims, String subject) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + appProperties.getAuth().getTokenExpirationMsec());
        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS256, appProperties.getAuth().getTokenSecret()).compact();
    }

    private String createRefreshToken(String subject) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + appProperties.getAuth().getRefreshTokenExpirationMsec());
        return Jwts.builder().setSubject(subject).setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS256, appProperties.getAuth().getTokenSecret()).compact();
    }

    private String createStationToken(Map<String, Object> claims, String subject, Date expiration) throws Exception {
        if (expiration.before(new Date())) {
            throw new Exception("Expiration cannot be before now");
        }
        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date())
                .setExpiration(expiration)
                .signWith(SignatureAlgorithm.HS256, appProperties.getAuth().getTokenSecret()).compact();
    }

    private String createStationToken(Map<String, Object> claims, String subject) {
        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date())
                .signWith(SignatureAlgorithm.HS256, appProperties.getAuth().getTokenSecret()).compact();
    }

    public Boolean validateTokenForStation(String token, Station station) {
        final Long id = Long.parseLong(extractSubject(token));
        return (id.equals(station.getId()));
    }

    public boolean validateToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(appProperties.getAuth().getTokenSecret()).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException ex) {
            logger.error("Invalid JWT signature");
        } catch (MalformedJwtException ex) {
            logger.error("Invalid JWT token");
        } catch (ExpiredJwtException ex) {
            logger.error("Expired JWT token");
        } catch (UnsupportedJwtException ex) {
            logger.error("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            logger.error("JWT claims string is empty.");
        }
        return false;
    }
}