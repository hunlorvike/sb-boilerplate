package hun.lorvike.boilerplate.security;

import hun.lorvike.boilerplate.configurations.JwtConfig;
import hun.lorvike.boilerplate.entities.User;
import hun.lorvike.boilerplate.repositories.IUserRepository;
import io.jsonwebtoken.*;
<<<<<<< HEAD
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.security.*;
=======
import io.jsonwebtoken.security.Keys;
>>>>>>> 22acfaa4cdb0d5f0597cb69081d70d53a4efe2c1
import jakarta.servlet.http.HttpServletRequest;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;

import java.util.Date;
import java.util.Optional;
import javax.crypto.SecretKey;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@Data
public class JwtService implements IJwtService {

    private final IUserRepository userRepository;
    private final SecretKey secretKey;
    private final Long expirationToken;
    private final Long expirationRefreshToken;
    private final Long expirationRememberMe;
    private final HttpServletRequest httpServletRequest;

    public JwtService(
            IUserRepository userRepository,
            JwtConfig jwtConfig,
            HttpServletRequest httpServletRequest) {
        this.userRepository = userRepository;
        this.secretKey = Keys.hmacShaKeyFor(jwtConfig.getSecretKey().getBytes());
        this.expirationToken = jwtConfig.getExpirationToken();
        this.expirationRefreshToken = jwtConfig.getExpirationRefreshToken();
        this.expirationRememberMe = jwtConfig.getExpirationRememberMe();
        this.httpServletRequest = httpServletRequest;
    }

    @Override
    public String generateToken(UserDetails userDetails) {
        return buildToken(userDetails, "access_token", expirationToken);
    }

    @Override
    public String generateRefreshToken(UserDetails userDetails) {
        return buildToken(userDetails, "refresh_token", expirationRefreshToken);
    }

    @Override
    public String generateRememberMe(UserDetails userDetails) {
        return buildToken(userDetails, "remember_me_token", expirationRememberMe);
    }

    @Override
    public String refreshAccessToken(String refreshToken) {
        try {
            String username = extractUsername(refreshToken);
            if (username != null && validateRefreshToken(refreshToken, username)) {
                Claims claims = getClaims(refreshToken);
                if (claims.get("type").equals("refresh_token")) {
                    Optional<User> userOptional = userRepository.findByEmail(username);
                    if (userOptional.isPresent()) {
                        User user = userOptional.get();
                        return generateToken(User.build(user));
                    } else {
                        log.error("User not found while refreshing access token");
                        throw new JwtServiceException(
                                "User not found while refreshing access token");
                    }
                } else {
                    log.error("Invalid token type while refreshing access token");
                    throw new IllegalArgumentException(
                            "Invalid token type while refreshing access token");
                }
            } else {
                log.error(
                        "Invalid refresh token or username while refreshing access token");
                throw new IllegalArgumentException(
                        "Invalid refresh token or username while refreshing access token");
            }
        } catch (Exception e) {
            log.error("Error refreshing access token", e);
            throw new JwtServiceException("Error refreshing access token", e);
        }
    }

    @Override
    public Claims getClaims(String token) {
        try {
            return Jwts
                    .parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(removeBearerPrefix(token))
                    .getPayload();
        } catch (Exception e) {
            log.error("Error parsing claims from JWT: {}", e.getMessage());
            throw new JwtServiceException("Error parsing claims from JWT", e);
        }
    }

    @Override
    public String removeBearerPrefix(String token) {
        return (token != null && token.startsWith("Bearer ")) ? token.substring(7) : token;
    }

    @Override
    public boolean validateToken(String token) {
        try {
            Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token);
            return true;
        } catch (Exception e) {
            log.warn("Invalid JWT token: {}", e.getMessage());
            return false;
        }
    }

    @Override
    public boolean validateToken(String token, boolean isHttp) {
        try {
            parseToken(token);
            if (isHttp) {
                String userAgentHeader = httpServletRequest.getHeader("User-Agent");
                if (userAgentHeader == null || userAgentHeader.isEmpty()) {
                    log.error("[JWT] User-Agent header is missing");
                    return false;
                }
            }
        } catch (Exception e) {
            log.error("Error validating token", e);
            return false;
        }

        return !isTokenExpired(token);
    }

    @Override
    public boolean validateToken(String token, HttpServletRequest request) {
        try {
            boolean isTokenValid = validateToken(token);
            if (!isTokenValid) {
                log.error("[JWT] Token could not be found in local cache");
                request.setAttribute("notfound", "Token is not found in cache");
            }
            return isTokenValid;
        } catch (UnsupportedJwtException e) {
            log.error("[JWT] Unsupported JWT token!");
            request.setAttribute("unsupported", "Unsupported JWT token!");
        } catch (MalformedJwtException e) {
            log.error("[JWT] Invalid JWT token!");
            request.setAttribute("invalid", "Invalid JWT token!");
        } catch (ExpiredJwtException e) {
            log.error("[JWT] Expired JWT token!");
            request.setAttribute("expired", "Expired JWT token!");
        } catch (IllegalArgumentException e) {
            log.error("[JWT] Jwt claims string is empty");
            request.setAttribute("illegal", "JWT claims string is empty.");
        } catch (SignatureException e) {
            log.error("[JWT] Invalid token signature");
            request.setAttribute("signature_invalid", "Invalid token signature");
        } catch (PrematureJwtException e) {
            log.error("[JWT] Premature JWT token");
            request.setAttribute("premature", "Premature JWT token");
        } catch (Exception e) {
            log.error("[JWT] An unexpected error occurred during token validation");
            request.setAttribute("unexpected_error", "An unexpected error occurred during token validation");
        }

        return false;
    }

    @Override
    public String extractUsername(String token) {
        try {
            return getClaims(removeBearerPrefix(token)).getSubject();
        } catch (Exception e) {
            log.error("Error extracting username from JWT: {}", e.getMessage());
            throw new JwtServiceException("Error extracting username from JWT", e);
        }
    }

    private boolean validateRefreshToken(String refreshToken, String username) {
        try {
            Claims claims = getClaims(refreshToken);
            return (username.equals(claims.getSubject()) &&
                    !claims.getExpiration().before(new Date()));
        } catch (Exception e) {
            log.error("Error validating refresh token", e);
            return false;
        }
    }

    @Override
    public String extractJwtFromRequest(HttpServletRequest request) {
        return removeBearerPrefix(request.getHeader("Authorization"));
    }

    @Override
    public Jws<Claims> parseToken(String token) {
        try {
            return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(removeBearerPrefix(token));
        } catch (Exception e) {
            log.error("Error parsing JWT token: {}", e.getMessage(), e);
            throw new JwtServiceException("Error parsing JWT token", e);
        }
    }

    @Override
    public boolean isTokenExpired(String token) {
        try {
            Claims claims = parseToken(token).getPayload();
            return claims.getExpiration().before(new Date());
        } catch (Exception e) {
            log.error("Error checking token expiration: {}", e.getMessage(), e);
            throw new JwtServiceException("Error checking token expiration", e);
        }
    }

    @Override
    public boolean revokeToken(String token) {
        throw new UnsupportedOperationException("Unimplemented method 'revokeToken'");
    }

    @Override
    public String refreshTokenIfExpired(String token) {
        try {
            if (isTokenExpired(token)) {
                log.info("Token expired, refreshing access token");
                return refreshAccessToken(token);
            } else {
                log.info("Token is not expired, no need to refresh");
                return token;
            }
        } catch (Exception e) {
            log.error("Error refreshing access token if expired", e);
            throw new JwtServiceException("Error refreshing access token if expired", e);
        }
    }

    private String buildToken(UserDetails userDetails, String type, Long expiration) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration);
        log.trace("Token is added to the local cache for username: {}", userDetails.getUsername());

        return Jwts.builder()
                .claim("sub", userDetails.getUsername())
                .claim("iat", now.getTime())
                .claim("exp", expiryDate.getTime())
                .claim("type", type)
                .claim("role", userDetails.getAuthorities())
<<<<<<< HEAD
                .signWith(this.secretKey, SignatureAlgorithm.HS512)
=======
                .signWith(secretKey, SignatureAlgorithm.HS512)
>>>>>>> 22acfaa4cdb0d5f0597cb69081d70d53a4efe2c1
                .compact();
    }
}

class JwtServiceException extends RuntimeException {

    public JwtServiceException(String message) {
        super(message);
    }

    public JwtServiceException(String message, Throwable cause) {
        super(message, cause);
    }
}
