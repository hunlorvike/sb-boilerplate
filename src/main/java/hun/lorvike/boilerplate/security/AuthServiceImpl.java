package hun.lorvike.boilerplate.security;

import hun.lorvike.boilerplate.configurations.enums.ERole;
import hun.lorvike.boilerplate.dtos.auth.LoginDto;
import hun.lorvike.boilerplate.dtos.auth.RegisterDto;
import hun.lorvike.boilerplate.dtos.auth.ResLoginDto;
import hun.lorvike.boilerplate.entities.User;
import hun.lorvike.boilerplate.repositories.IUserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements IAuthService {
    private final IUserRepository iUserRepository;
    private final PasswordEncoder passwordEncoder;
    private final IJwtService iJwtService;
    private final AuthenticationManager authenticationManager;

    @Override
    @Transactional(rollbackOn = Exception.class)
    public User registerUser(RegisterDto registerDto) {
        try {
            Optional<User> userOptional = iUserRepository.findByEmail(registerDto.getEmail());

            if (userOptional.isPresent()) {
                throw new IllegalArgumentException("User with the provided email already exists");
            }

            User newUser = new User();
            newUser.setName(registerDto.getName());
            newUser.setEmail(registerDto.getEmail());
            newUser.setPassword(passwordEncoder.encode(registerDto.getPassword()));
            newUser.setRole(ERole.USER);
            newUser.setAgency(null);

            User savedUser = iUserRepository.save(newUser);
            UserDetails userDetails = User.build(savedUser);

            String refreshToken = iJwtService.generateRefreshToken(userDetails);
            savedUser.setRefreshToken(refreshToken);
            return savedUser;

        } catch (Exception e) {
            throw new RuntimeException("Unexpected error during user registration", e);
        }
    }

    @Override
    public ResLoginDto authenticateUser(LoginDto loginDto) {
        try {
            Optional<User> userOptional = iUserRepository.findByEmail(loginDto.getEmail());
            if (userOptional.isPresent()) {
                User user = userOptional.get();
                UserDetails userDetails = User.build(user);

                Authentication authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, userDetails.getPassword(), userDetails.getAuthorities());

                SecurityContextHolder.getContext().setAuthentication(authentication);

                String accessToken = iJwtService.generateToken(userDetails);
                String refreshToken = iJwtService.generateRefreshToken(userDetails);

                Date now = new Date();
                long expirationTime = 3600000L;
                Date expirationDate = new Date(now.getTime() + expirationTime);

                ResLoginDto resLoginDto = new ResLoginDto();
                resLoginDto.setAccessToken(accessToken);
                resLoginDto.setRefreshToken(refreshToken);
                resLoginDto.setTokenType("Bearer");
                resLoginDto.setExpiresIn(expirationDate.getTime());

                return resLoginDto;
            }
        } catch (Exception e) {
            throw new RuntimeException("Authentication failed", e);
        }
        return null;
    }

}
