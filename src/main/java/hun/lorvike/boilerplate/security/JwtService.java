package hun.lorvike.boilerplate.security;

import hun.lorvike.boilerplate.entities.User;
import hun.lorvike.boilerplate.repositories.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

import java.util.Date;
import java.util.Optional;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.crossstore.ChangeSetPersister.NotFoundException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class JwtService implements IJwtService {

	private final UserRepository userRepository;
	private final SecretKey secretKey;
	private final Long expirationToken;
	private final Long expirationRefreshToken;
	private final Long expirationRememberMe;
	private final HttpServletRequest httpServletRequest;

	public JwtService(
			UserRepository userRepository,
			@Value("${app.secret}") String secretKey,
			@Value("${app.jwt.token.expires-in}") Long expirationToken,
			@Value("${app.jwt.refresh-token.expires-in}") Long expirationRefreshToken,
			@Value("${app.jwt.remember-me.expires-in}") Long expirationRememberMe,
			HttpServletRequest httpServletRequest) {
		this.userRepository = userRepository;
		this.secretKey = Keys.hmacShaKeyFor(secretKey.getBytes());
		this.expirationToken = expirationToken;
		this.expirationRefreshToken = expirationRefreshToken;
		this.expirationRememberMe = expirationRememberMe;
		this.httpServletRequest = httpServletRequest;
	}

	@Override
	public String generateToken(UserDetails userDetails) {
		Date now = new Date();
		Date expiryDate = new Date(now.getTime() + expirationToken);

		return Jwts
				.builder()
				.setSubject(userDetails.getUsername())
				.setIssuedAt(now)
				.setExpiration(expiryDate)
				.claim("type", "access_token")
				.signWith(secretKey, SignatureAlgorithm.HS512)
				.compact();
	}

	@Override
	public String generateRefreshToken(UserDetails userDetails) {
		Date now = new Date();
		Date expiryDate = new Date(now.getTime() + expirationRefreshToken);

		return Jwts
				.builder()
				.setSubject(userDetails.getUsername())
				.setIssuedAt(now)
				.setExpiration(expiryDate)
				.claim("type", "refresh_token")
				.signWith(secretKey, SignatureAlgorithm.HS512)
				.compact();
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
						throw new RuntimeException(
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
			throw new RuntimeException("Error refreshing access token", e);
		}
	}

	@Override
	public String generateRememberMe(UserDetails userDetails) {
		Date now = new Date();
		Date expiryDate = new Date(now.getTime() + expirationRememberMe);

		return Jwts
				.builder()
				.setSubject(userDetails.getUsername())
				.setIssuedAt(now)
				.setExpiration(expiryDate)
				.claim("type", "remember_me_token")
				.signWith(secretKey, SignatureAlgorithm.HS512)
				.compact();
	}

	@Override
	public Claims getClaims(String token) {
		try {
			return Jwts
					.parser()
					.setSigningKey(secretKey)
					.build()
					.parseClaimsJws(removeBearerPrefix(token))
					.getBody();
		} catch (Exception e) {
			log.error("Error parsing claims from JWT: {}", e.getMessage());
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
			if(!isTokenValid) {
				log.error("[JWT] Token could not found in local cache");
                httpServletRequest.setAttribute("notfound", "Token is not found in cache");
			}
			return isTokenValid;
		} catch (UnsupportedJwtException e) {
            log.error("[JWT] Unsupported JWT token!");
            httpServletRequest.setAttribute("unsupported", "Unsupported JWT token!");
        } catch (MalformedJwtException e) {
            log.error("[JWT] Invalid JWT token!");
            httpServletRequest.setAttribute("invalid", "Invalid JWT token!");
        } catch (ExpiredJwtException e) {
            log.error("[JWT] Expired JWT token!");
            httpServletRequest.setAttribute("expired", "Expired JWT token!");
        } catch (IllegalArgumentException e) {
            log.error("[JWT] Jwt claims string is empty");
            httpServletRequest.setAttribute("illegal", "JWT claims string is empty.");
        }

        return false;
	}

	@Override
	public String extractUsername(String token) {
		try {
			return getClaims(removeBearerPrefix(token)).getSubject();
		} catch (Exception e) {
			log.error("Error extracting username from JWT: {}", e.getMessage());
			throw new RuntimeException("Error extracting username from JWT", e);
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
		return Jwts.parser().setSigningKey(secretKey).build().parseClaimsJws(removeBearerPrefix(token));
	}

	@Override
	public boolean isTokenExpired(String token) {
		return parseToken(token).getBody().getExpiration().before(new Date());
	}

	@Override
	public boolean revokeToken(String token) {
		// TODO Auto-generated method stub
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
			throw new RuntimeException("Error refreshing access token if expired", e);
		}
	}

}
