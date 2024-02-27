package hun.lorvike.boilerplate.security;

import jakarta.transaction.Transactional;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import hun.lorvike.boilerplate.entities.User;
import hun.lorvike.boilerplate.repositories.IUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

@Component
@Slf4j
@RequiredArgsConstructor
public class CustomAuthenticationManager implements AuthenticationManager {
    private final PasswordEncoder passwordEncoder;
    private final IUserRepository IUserRepository;

    @Override
    @Transactional
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Optional<User> userOptional = IUserRepository.findByEmail(authentication.getName());

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
                throw new BadCredentialsException("Mật khẩu không đúng.");
            }
        } else {
            log.error("User not found for email {}", authentication.getName());
            throw new UsernameNotFoundException("Không tìm thấy người dùng với email: " + authentication.getName());
        }
    }

}