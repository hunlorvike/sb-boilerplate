package hun.lorvike.boilerplate.services.impls;

import hun.lorvike.boilerplate.entities.User;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
public class EmailServiceImpl {
    @Setter
    private static JavaMailSender javaMailSender;

    @Value("${spring.mail.username}")
    private static String sender;

    public static boolean sendVerificationEmail(User user, String subject, String body) {
        if (javaMailSender == null) {
            throw new IllegalStateException("JavaMailSender has not been set. Call setJavaMailSender before using this method.");
        }

        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(sender);
            message.setTo(user.getEmail());
            message.setSubject(subject);
            message.setText(body);

            javaMailSender.send(message);

            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static void sendVerificationEmail(User user, String token) {
        String verificationLink = "http://localhost:8080/api/auth/verify-email?userId=" + user.getId() + "&token=" + token;
        String emailBody = "Please click the following link to verify your email: " + verificationLink;

        boolean status = EmailServiceImpl.sendVerificationEmail(user, "Verify Email", emailBody);

        if (!status) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to send verification email. Rolling back transaction.");
        }
    }


}
