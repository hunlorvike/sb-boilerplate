package hun.lorvike.boilerplate.utils;



import java.util.UUID;

public class AuthUtil {

    public static String generateVerificationToken() {
        return UUID.randomUUID().toString();
    }
}
