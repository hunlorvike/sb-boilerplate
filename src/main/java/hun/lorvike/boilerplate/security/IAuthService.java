package hun.lorvike.boilerplate.security;

import hun.lorvike.boilerplate.dtos.auth.LoginDto;
import hun.lorvike.boilerplate.dtos.auth.RegisterDto;
import hun.lorvike.boilerplate.dtos.auth.ResLoginDto;
import hun.lorvike.boilerplate.entities.User;

import java.util.concurrent.CompletableFuture;

public interface IAuthService {

    CompletableFuture<User> registerUserAsync(RegisterDto registerDto);

    CompletableFuture<ResLoginDto> authenticateUserAsync(LoginDto loginDto);
}
