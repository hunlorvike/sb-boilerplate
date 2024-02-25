package hun.lorvike.boilerplate.security;

import hun.lorvike.boilerplate.entities.User;
import hun.lorvike.boilerplate.repositories.UserRepository;
import hun.lorvike.boilerplate.security.IJwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Optional;

@Service
public class JwtService implements IJwtService {
    private static final Logger logger = LoggerFactory.getLogger(JwtService.class);
    private final UserRepository userRepository;
    private final SecretKey secretKey;
    private final Long expirationToken;
    private final Long expirationRefreshToken;
    private final Long expirationRememberMe;

    public JwtService(UserRepository userRepository,
                      @Value("${app.secret}") String secretKey,
                      @Value("${app.jwt.token.expires-in}") Long expirationToken,
                      @Value("${app.jwt.refresh-token.expires-in}") Long expirationRefreshToken,
                      @Value("${app.jwt.remember-me.expires-in}") Long expirationRememberMe) {
        this.userRepository = userRepository;
        this.secretKey = Keys.hmacShaKeyFor(secretKey.getBytes());
        this.expirationToken = expirationToken;
        this.expirationRefreshToken = expirationRefreshToken;
        this.expirationRememberMe = expirationRememberMe;
    }

    @Override
    public String generateToken(UserDetails userDetails) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationToken);

        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(secretKey, SignatureAlgorithm.HS512)
                .compact();
    }

    @Override
    public String generateRefreshToken(UserDetails userDetails) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationRefreshToken);

        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(secretKey, SignatureAlgorithm.HS512)
                .compact();
    }

    @Override
    public String refreshAccessToken(String refreshToken) {
        try {
            String username = extractUsername(refreshToken);
            if (username != null && validateRefreshToken(refreshToken, username)) {
                Optional<User> userOptional = userRepository.findByEmail(username);
                return userOptional.map(user -> generateToken(User.build(user))).orElse(null);
            }
        } catch (Exception e) {
            logger.error("Error refreshing access token", e);
        }
        return null;
    }

    @Override
    public String generateRememberMe(UserDetails userDetails) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationRememberMe);

        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(secretKey, SignatureAlgorithm.HS512)
                .compact();
    }

    @Override
    public Claims getClaims(String token) {
        try {
            return Jwts.parser().setSigningKey(secretKey).build().parseClaimsJws(removeBearerPrefix(token)).getBody();
        } catch (Exception e) {
            logger.error("Error parsing claims from JWT: {}", e.getMessage());
            throw new RuntimeException("Error parsing claims from JWT", e);
        }
    }

    @Override
    public String removeBearerPrefix(String token) {
        if (token.startsWith("Bearer ")) {
            return token.substring(7);
        }
        return token;
    }

    @Override
    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(secretKey).build().parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            logger.warn("Invalid JWT token: {}", e.getMessage());
            return false;
        }
    }

    @Override
    public String extractUsername(String token) {
        try {
            return getClaims(removeBearerPrefix(token)).getSubject();
        } catch (Exception e) {
            logger.error("Error extracting username from JWT: {}", e.getMessage());
            throw new RuntimeException("Error extracting username from JWT", e);
        }
    }

    private boolean validateRefreshToken(String refreshToken, String username) {
        try {
            Claims claims = getClaims(refreshToken);
            return username.equals(claims.getSubject()) && !claims.getExpiration().before(new Date());
        } catch (Exception e) {
            logger.error("Error validating refresh token", e);
            return false;
        }
    }
}
