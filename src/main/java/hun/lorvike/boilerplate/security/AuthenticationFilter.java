package hun.lorvike.boilerplate.security;

import java.io.IOException;
import java.util.Optional;

import hun.lorvike.boilerplate.entities.User;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
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
@RequiredArgsConstructor
public class AuthenticationFilter extends OncePerRequestFilter {
    private final IJwtService iJwtService;
    private final IUserRepository userRepository;
    private final AuthenticationManager authenticationManager;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        try {
            String token = iJwtService.extractJwtFromRequest(request);

            if (StringUtils.hasText(token) && iJwtService.validateToken(token, request)) {
                String username = iJwtService.extractUsername(token);
                Optional<User> userOptional = userRepository.findByEmail(username);

                if (userOptional.isPresent()) {
                    performAuthentication(request, response, userOptional.get());
                }
            }
        } catch (ExpiredJwtException e) {
            handleJwtException(response, "JWT token expired", e.getClaims().getSubject());
            return;
        } catch (JwtException e) {
            handleJwtException(response, "Invalid JWT token", e.getMessage());
            return;
        }

        filterChain.doFilter(request, response);
        log.info("Request from {}", request.getRemoteAddr());
    }

    private void performAuthentication(HttpServletRequest request, HttpServletResponse response, User user)
            throws IOException {
        UserDetails userDetails = User.build(user);
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                userDetails, userDetails.getPassword(), userDetails.getAuthorities());

        try {
            Authentication authenticated = authenticationManager.authenticate(authentication);

            if (authenticated.isAuthenticated()) {
                SecurityContextHolder.getContext().setAuthentication(authenticated);
                request.setAttribute("user", user);
                log.info("User {} successfully authenticated", user.getEmail());
            } else {
                log.warn("Authentication failed for user {}", user.getEmail());
                response.sendError(HttpServletResponse.SC_FORBIDDEN,
                        "Access denied: User does not have the required permissions");
            }
        } catch (AuthenticationException e) {
            log.warn("Authentication failed for user {}: {}", user.getEmail(), e.getMessage());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication failed");
        }
    }

    private void handleJwtException(HttpServletResponse response, String errorMessage, String subject)
            throws IOException {
        log.warn("{} for user {}", errorMessage, subject);
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, errorMessage);
    }
}
