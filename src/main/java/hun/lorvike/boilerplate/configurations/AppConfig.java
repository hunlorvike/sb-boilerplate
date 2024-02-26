package hun.lorvike.boilerplate.configurations;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.i18n.AcceptHeaderLocaleResolver;

import java.util.Locale;
import java.util.TimeZone;

@Configuration
public class AppConfig {

    @Bean
    public LocaleResolver localeResolver(@Value("${app.default-locale:en}") final String defaultLocale,
                                         @Value("${app.default-timezone:UTC}") final String defaultTimezone) {
        AcceptHeaderLocaleResolver localResolver = new AcceptHeaderLocaleResolver();
        localResolver.setDefaultLocale(new Locale(defaultLocale));
        TimeZone.setDefault(TimeZone.getTimeZone(defaultTimezone));

        return localResolver;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
