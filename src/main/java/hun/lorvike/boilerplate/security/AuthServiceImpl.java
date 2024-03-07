package hun.lorvike.boilerplate.security;

import hun.lorvike.boilerplate.configurations.configs.JwtConfig;
import hun.lorvike.boilerplate.dtos.auth.LoginDto;
import hun.lorvike.boilerplate.dtos.auth.RegisterDto;
import hun.lorvike.boilerplate.dtos.auth.res.ResLoginDto;
import hun.lorvike.boilerplate.dtos.auth.res.ResRegisterDto;
import hun.lorvike.boilerplate.dtos.auth.res.ResVerifyDto;
import hun.lorvike.boilerplate.entities.User;
import hun.lorvike.boilerplate.entities.VerificationToken;
import hun.lorvike.boilerplate.repositories.IUserRepository;
import hun.lorvike.boilerplate.repositories.IVerificationToken;
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
    private final IVerificationToken verificationTokenRepository;


    public AuthServiceImpl(IUserRepository userRepository, PasswordEncoder passwordEncoder, IJwtService jwtService, UserDetailsService userDetailsService, JwtConfig jwtConfig, IVerificationToken verificationTokenRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
        this.expirationToken = jwtConfig.getExpirationToken();
        this.verificationTokenRepository = verificationTokenRepository;
    }

    @Override
    @Transactional(rollbackOn = Exception.class)
    public CompletableFuture<ResRegisterDto> registerUserAsync(RegisterDto registerDto) {
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

                String token = AuthUtil.generateVerificationToken();

                VerificationToken verificationToken = new VerificationToken();
                verificationToken.setUser(savedUser);
                verificationToken.setToken(token);
                verificationTokenRepository.save(verificationToken);

                savedUser.setVerificationToken(verificationToken);
                userRepository.save(savedUser);

                EmailServiceImpl.sendVerificationEmail(savedUser, token);

                String refreshToken = jwtService.generateRefreshToken(userDetails);
                savedUser.setRefreshToken(refreshToken);
                log.info("User registered successfully with email: {}", registerDto.getEmail());
                return new ResRegisterDto("Registration successful. Check your email for verification instructions.");
            } catch (DataIntegrityViolationException e) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Data integrity violation during user registration", e);
            } catch (Exception e) {
                throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Unexpected error during user registration " + e.getMessage());
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
    public CompletableFuture<ResVerifyDto> verifyEmail(Long userId, String token) {
        return CompletableFuture.supplyAsync(() -> {
            Optional<User> userOptional = userRepository.findById(userId);

            if (userOptional.isPresent()) {
                User user = userOptional.get();
                VerificationToken verificationToken = user.getVerificationToken();

                if (verificationToken != null && Objects.equals(verificationToken.getToken(), token)) {
                    user.setEnabled(true);
                    userRepository.save(user);
                    return new ResVerifyDto("Email verification successful. You can now log in.");
                } else {
                    return new ResVerifyDto("Invalid verification token.");
                }
            } else {
                return new ResVerifyDto("User not found");
            }
        });
    }

}
