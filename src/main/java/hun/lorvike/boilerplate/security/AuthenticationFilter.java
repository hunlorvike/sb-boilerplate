package hun.lorvike.boilerplate.security;

import hun.lorvike.boilerplate.entities.User;
import hun.lorvike.boilerplate.repositories.IUserRepository;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

@Component
@Slf4j
@RequiredArgsConstructor
public class AuthenticationFilter extends OncePerRequestFilter {
    private final IJwtService iJwtService;
    private final IUserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        try {
            String token = iJwtService.extractJwtFromRequest(request);

            if (StringUtils.hasText(token) && iJwtService.validateToken(token, request)) {
                String username = iJwtService.extractUsername(token);
                Optional<User> userOptional = userRepository.findByEmail(username);

                if (userOptional.isPresent()) {
                    performAuthentication(request, response, userOptional.get());
                }
            } else {
                log.info("No valid token found in the Authorization header. Allowing the request to proceed without authentication.");
            }
        } catch (ExpiredJwtException e) {
            handleJwtException(response, "JWT token expired", e.getClaims().getSubject());
            return;
        } catch (JwtException e) {
            handleJwtException(response, "Invalid JWT token", e.getMessage());
            return;
        }
        log.info("Request from authentication filter {}", request.getRemoteAddr());
        filterChain.doFilter(request, response);
    }

    private void performAuthentication(HttpServletRequest request, HttpServletResponse response, User user)
            throws IOException {
        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                userDetails, userDetails.getPassword(), userDetails.getAuthorities());

        authentication.setDetails(userDetails);
        try {
            Authentication authenticated = authenticationManager.authenticate(authentication);

            SecurityContextHolder.getContext().setAuthentication(authenticated);

            request.setAttribute("user", user);

            log.info("User {} successfully authenticated", user.getUsername());
        } catch (AuthenticationException e) {
            log.warn("Authentication failed for user {}: {}", user.getUsername(), e.getMessage());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication failed");
        }
    }

    private void handleJwtException(HttpServletResponse response, String errorMessage, String subject)
            throws IOException {
        log.warn("{} for user {}", errorMessage, subject);
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, errorMessage);
    }
}
