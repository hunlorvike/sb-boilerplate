package hun.lorvike.boilerplate.configurations;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import lombok.*;

@Configuration
@Data
@Getter
@Setter
public class JwtConfig {

    @Value("${app.secret}")
    private String secretKey;

    @Value("${app.jwt.token.expires-in}")
    private Long expirationToken;

    @Value("${app.jwt.refresh-token.expires-in}")
    private Long expirationRefreshToken;

    @Value("${app.jwt.remember-me.expires-in}")
    private Long expirationRememberMe;
}
