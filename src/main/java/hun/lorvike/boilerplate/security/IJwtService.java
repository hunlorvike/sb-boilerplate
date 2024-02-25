package hun.lorvike.boilerplate.security;

import io.jsonwebtoken.Claims;
import org.springframework.security.core.userdetails.UserDetails;

public interface IJwtService {
    String generateToken(UserDetails userDetails);

    String refreshAccessToken(String refreshToken);

    String generateRefreshToken(UserDetails userDetails);

    String generateRememberMe(UserDetails userDetails);

    Claims getClaims(String token);

    String removeBearerPrefix(String token);

    boolean validateToken(String token);

    String extractUsername(String token);
}
