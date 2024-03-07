package hun.lorvike.boilerplate.security;

import hun.lorvike.boilerplate.dtos.auth.LoginDto;
import hun.lorvike.boilerplate.dtos.auth.RegisterDto;
import hun.lorvike.boilerplate.dtos.auth.res.ResLoginDto;
import hun.lorvike.boilerplate.dtos.auth.res.ResRegisterDto;
import hun.lorvike.boilerplate.dtos.auth.res.ResVerifyDto;

import java.util.concurrent.CompletableFuture;

public interface IAuthService {

    CompletableFuture<ResRegisterDto> registerUserAsync(RegisterDto registerDto);

    CompletableFuture<ResLoginDto> authenticateUserAsync(LoginDto loginDto);

    CompletableFuture<ResVerifyDto> verifyEmail(Long userId, String token);
}
