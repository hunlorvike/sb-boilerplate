package hun.lorvike.boilerplate.services.impls;

import hun.lorvike.boilerplate.entities.User;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailServiceImpl {
    private static JavaMailSender javaMailSender;

    @Value("${spring.mail.username}")
    private static String sender;

    public static void setJavaMailSender(JavaMailSender mailSender) {
        javaMailSender = mailSender;
    }

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

}
