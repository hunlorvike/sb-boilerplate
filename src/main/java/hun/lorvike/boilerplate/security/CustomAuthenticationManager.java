package hun.lorvike.boilerplate.security;

import jakarta.transaction.Transactional;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import hun.lorvike.boilerplate.entities.User;
import hun.lorvike.boilerplate.repositories.IUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.server.ResponseStatusException;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

@Component
@Slf4j
@RequiredArgsConstructor
public class CustomAuthenticationManager implements AuthenticationManager {
    private final IUserRepository userRepository;

    @Override
    @Transactional
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Optional<User> userOptional = userRepository.findByEmail(authentication.getName());

        if (userOptional.isPresent()) {
            User user = userOptional.get();
            UserDetails userDetails = User.build(user);

            boolean matches = authentication.getCredentials() != null &&
                    authentication.getCredentials().equals(userDetails.getPassword());

            if (matches) {
                List<SimpleGrantedAuthority> authorities = Collections.singletonList(
                        new SimpleGrantedAuthority("ROLE_" + user.getRole().name()));

                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, authorities);
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                return authenticationToken;
            } else {
                log.error("Authentication failed for {}", authentication.getName());
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Incorrect password.");
            }
        } else {
            log.error("User not found for email {}", authentication.getName());
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found with email: " + authentication.getName());
        }
    }
}
