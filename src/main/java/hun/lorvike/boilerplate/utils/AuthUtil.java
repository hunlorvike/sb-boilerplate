package hun.lorvike.boilerplate.utils;

import hun.lorvike.boilerplate.entities.User;
import hun.lorvike.boilerplate.entities.VerificationToken;

import java.util.UUID;

public class AuthUtil {

    public static String generateVerificationToken(User user) {
        String token = UUID.randomUUID().toString();

        VerificationToken verificationToken = new VerificationToken();
        verificationToken.setToken(token);
        verificationToken.setUser(user);

        user.setVerificationToken(verificationToken);

        return token;
    }
}
