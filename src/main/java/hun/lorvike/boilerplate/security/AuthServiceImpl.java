package hun.lorvike.boilerplate.security;

import hun.lorvike.boilerplate.configurations.configs.JwtConfig;
import hun.lorvike.boilerplate.dtos.auth.LoginDto;
import hun.lorvike.boilerplate.dtos.auth.RegisterDto;
import hun.lorvike.boilerplate.dtos.auth.ResLoginDto;
import hun.lorvike.boilerplate.entities.User;
import hun.lorvike.boilerplate.entities.VerificationToken;
import hun.lorvike.boilerplate.repositories.IUserRepository;
import hun.lorvike.boilerplate.services.impls.EmailServiceImpl;
import hun.lorvike.boilerplate.utils.AuthUtil;
import hun.lorvike.boilerplate.utils.enums.ERole;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.TransactionSystemException;
import org.springframework.web.server.ResponseStatusException;

import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

@Service
@Slf4j
public class AuthServiceImpl implements IAuthService {

    private final IUserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final IJwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final Long expirationToken;

    public AuthServiceImpl(IUserRepository userRepository, PasswordEncoder passwordEncoder, IJwtService jwtService, UserDetailsService userDetailsService, JwtConfig jwtConfig) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
        this.expirationToken = jwtConfig.getExpirationToken();
    }

    @Override
    @Transactional(rollbackOn = Exception.class)
    public CompletableFuture<User> registerUserAsync(RegisterDto registerDto) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                log.info("Attempting to register user with email: {}", registerDto.getEmail());
                Optional<User> userOptional = userRepository.findByEmail(registerDto.getEmail());

                if (userOptional.isPresent()) {
                    log.error("User with email {} already exists.", registerDto.getEmail());
                    throw new ResponseStatusException(HttpStatus.CONFLICT, "User with the provided email already exists");
                }

                User newUser = new User();
                newUser.setName(registerDto.getName());
                newUser.setEmail(registerDto.getEmail());
                newUser.setPassword(passwordEncoder.encode(registerDto.getPassword()));
                newUser.setRole(ERole.USER);
                newUser.setAgency(null);

                User savedUser = userRepository.save(newUser);
                UserDetails userDetails = User.build(savedUser);

                String verificationToken = AuthUtil.generateVerificationToken(savedUser);

                String verificationLink = "http://localhost:8080/api/auth/verify-email?userId=" + savedUser.getId() + "&token=" + verificationToken;
                String emailBody = "Please click the following link to verify your email: " + verificationLink;

                boolean status = EmailServiceImpl.sendVerificationEmail(savedUser, "Verify Email", emailBody);

                if (!status) {
                    throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to send verification email. Rolling back transaction.");
                }

                String refreshToken = jwtService.generateRefreshToken(userDetails);
                savedUser.setRefreshToken(refreshToken);
                log.info("User registered successfully with email: {}", registerDto.getEmail());
                return savedUser;
            } catch (DataIntegrityViolationException e) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Data integrity violation during user registration", e);
            } catch (Exception e) {
                throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Unexpected error during user registration "+ e.getMessage());
            }
        });
    }

    @Override
    public CompletableFuture<ResLoginDto> authenticateUserAsync(LoginDto loginDto) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                log.info("Attempting to authenticate user with email: {}", loginDto.getEmail());
                Optional<User> userOptional = userRepository.findByEmail(loginDto.getEmail());
                if (userOptional.isPresent()) {
                    User user = userOptional.get();

                    if (passwordEncoder.matches(loginDto.getPassword(), user.getPassword())) {
                        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());

                        String accessToken = jwtService.generateToken(userDetails);
                        String refreshToken = jwtService.generateRefreshToken(userDetails);

                        ResLoginDto resLoginDto = new ResLoginDto();
                        resLoginDto.setAccessToken(accessToken);
                        resLoginDto.setRefreshToken(refreshToken);
                        resLoginDto.setTokenType("Bearer");
                        resLoginDto.setExpiresIn(expirationToken);

                        log.info("User authenticated successfully with email: {}", loginDto.getEmail());
                        return resLoginDto;
                    } else {
                        log.warn("Incorrect username or password for user with email: {}", loginDto.getEmail());
                        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Incorrect username or password");
                    }
                }
            } catch (ResponseStatusException e) {
                throw e;
            } catch (Exception e) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Incorrect username or password", e);
            }
            return null;
        });
    }

    @Override
    public CompletableFuture<String> verifyEmail(Long userId, String token) {
        return CompletableFuture.supplyAsync(() -> {
            Optional<User> userOptional = userRepository.findById(userId);

            if (userOptional.isPresent()) {
                User user = userOptional.get();
                VerificationToken verificationToken = user.getVerificationToken();

                if (verificationToken != null && Objects.equals(verificationToken.getToken(), token)) {
                    user.setEnabled(true);
                    userRepository.save(user);
                    return "Email verification successful. You can now log in.";
                } else {
                    return "Invalid verification token.";
                }
            } else {
                return "User not found.";
            }
        });
    }

}
