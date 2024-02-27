package hun.lorvike.boilerplate.security;

import java.io.IOException;
import java.util.Optional;

import hun.lorvike.boilerplate.entities.User;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import hun.lorvike.boilerplate.repositories.IUserRepository;
import org.springframework.util.StringUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class AuthenticationFilter extends OncePerRequestFilter {
    private final IJwtService iJwtService;
    private final IUserRepository IUserRepository;
    private final AuthenticationManager authenticationManager;

    @Autowired
    public AuthenticationFilter(IJwtService iJwtService, hun.lorvike.boilerplate.repositories.IUserRepository iUserRepository, AuthenticationManager authenticationManager) {
        this.iJwtService = iJwtService;
        IUserRepository = iUserRepository;
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        try {
            String token = iJwtService.extractJwtFromRequest(request);

            if (StringUtils.hasText(token) && iJwtService.validateToken(token, request)) {
                String username = iJwtService.extractUsername(token);
                Optional<User> userOptional = IUserRepository.findByEmail(username);

                if (userOptional.isPresent()) {
                    UserDetails userDetails = User.build(userOptional.get());
                    Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    Authentication authenticated = authenticationManager.authenticate(authentication);

                    if (authenticated.isAuthenticated()) {
                        SecurityContextHolder.getContext().setAuthentication(authenticated);
                        log.info("User {} successfully authenticated", username);
                    } else {
                        log.warn("Authentication failed for user {}", username);
                        response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied: User does not have the required permissions");
                        return;
                    }
                }
            }
        } catch (ExpiredJwtException e) {
            log.warn("JWT token expired for user {}", e.getClaims().getSubject());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "JWT token expired");
            return;
        } catch (JwtException e) {
            log.warn("Invalid JWT token: {}", e.getMessage());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid JWT token");
            return;
        } catch (AuthenticationException e) {
            log.warn("Authentication failed: {}", e.getMessage());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication failed");
            return;
        }

        filterChain.doFilter(request, response);
        log.info(request.getRemoteAddr());
    }

}
