package hun.lorvike.boilerplate.security;

import java.io.IOException;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import hun.lorvike.boilerplate.repositories.UserRepository;
import org.springframework.util.StringUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuthenticationFilter extends OncePerRequestFilter {
    private final IJwtService iJwtService;

    private final UserRepository userRepository;

    private final AuthenticationManager authenticationManager;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        String token = iJwtService.extractJwtFromRequest(request);
        if (StringUtils.hasText(token) && iJwtService.validateToken(token, request)) {
            String username = iJwtService.extractUsername(token);
            
        }
        throw new UnsupportedOperationException("Unimplemented method 'doFilterInternal'");
    }

}
