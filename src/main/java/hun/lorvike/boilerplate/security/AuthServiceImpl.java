package hun.lorvike.boilerplate.security;

import hun.lorvike.boilerplate.dtos.auth.LoginDto;
import hun.lorvike.boilerplate.dtos.auth.RegisterDto;
import hun.lorvike.boilerplate.dtos.auth.ResLoginDto;
import hun.lorvike.boilerplate.entities.User;
import hun.lorvike.boilerplate.repositories.IUserRepository;
import hun.lorvike.boilerplate.utils.enums.ERole;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements IAuthService {
    private final IUserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final IJwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    @Transactional(rollbackOn = Exception.class)
    public User registerUser(RegisterDto registerDto) {
        try {
            log.info("Attempting to register user with email: {}", registerDto.getEmail());
            Optional<User> userOptional = userRepository.findByEmail(registerDto.getEmail());

            if (userOptional.isPresent()) {
                log.error("User with email {} already exists.", registerDto.getEmail());
                throw new DataIntegrityViolationException("User with the provided email already exists");
            }

            User newUser = new User();
            newUser.setName(registerDto.getName());
            newUser.setEmail(registerDto.getEmail());
            newUser.setPassword(passwordEncoder.encode(registerDto.getPassword()));
            newUser.setRole(ERole.USER);
            newUser.setAgency(null);

            User savedUser = userRepository.save(newUser);
            UserDetails userDetails = User.build(savedUser);

            String refreshToken = jwtService.generateRefreshToken(userDetails);
            savedUser.setRefreshToken(refreshToken);
            log.info("User registered successfully with email: {}", registerDto.getEmail());
            return savedUser;

        } catch (Exception e) {
            throw new RuntimeException("Unexpected error during user registration", e);
        }
    }

    @Override
    public ResLoginDto authenticateUser(LoginDto loginDto) {
        try {
            log.info("Attempting to authenticate user with email: {}", loginDto.getEmail());
            Optional<User> userOptional = userRepository.findByEmail(loginDto.getEmail());
            if (userOptional.isPresent()) {
                User user = userOptional.get();
                UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());

                String accessToken = jwtService.generateToken(userDetails);
                String refreshToken = jwtService.generateRefreshToken(userDetails);

                Date now = new Date();
                long expirationTime = 3600000L;
                Date expirationDate = new Date(now.getTime() + expirationTime);

                ResLoginDto resLoginDto = new ResLoginDto();
                resLoginDto.setAccessToken(accessToken);
                resLoginDto.setRefreshToken(refreshToken);
                resLoginDto.setTokenType("Bearer");
                resLoginDto.setExpiresIn(expirationDate.getTime());

                log.info("User authenticated successfully with email: {}", loginDto.getEmail());
                return resLoginDto;
            }
        } catch (Exception e) {
            log.error("Authentication failed for user with email: {}", loginDto.getEmail(), e);
            throw new RuntimeException("Authentication failed", e);
        }
        return null;
    }
}
