package hun.lorvike.boilerplate.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.core.userdetails.UserDetails;

public interface IJwtService {
    String generateToken(UserDetails userDetails);

    String refreshAccessToken(String refreshToken);

    String generateRefreshToken(UserDetails userDetails);

    String generateRememberMe(UserDetails userDetails);

    Claims getClaims(String token);

    String removeBearerPrefix(String token);

    boolean validateToken(String token);

    boolean validateToken(String token, boolean isHttp);

    boolean validateToken(String token, HttpServletRequest request);

    String extractUsername(String token);

    String extractJwtFromRequest(HttpServletRequest request);

    Jws<Claims> parseToken(String token);

    boolean isTokenExpired(String token);

    boolean revokeToken(String token);

    String refreshTokenIfExpired(String token);

}
