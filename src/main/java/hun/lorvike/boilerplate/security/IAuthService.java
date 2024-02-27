package hun.lorvike.boilerplate.security;

import hun.lorvike.boilerplate.dtos.auth.LoginDto;
import hun.lorvike.boilerplate.dtos.auth.RegisterDto;
import hun.lorvike.boilerplate.dtos.auth.ResLoginDto;
import hun.lorvike.boilerplate.entities.User;

public interface IAuthService {

    User registerUser(RegisterDto registerDto);

    ResLoginDto authenticateUser(LoginDto loginDto);
}
