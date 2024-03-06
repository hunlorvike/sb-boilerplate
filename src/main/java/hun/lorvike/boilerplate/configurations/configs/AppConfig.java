package hun.lorvike.boilerplate.configurations.configs;

import hun.lorvike.boilerplate.utils.AuthUtil;
import hun.lorvike.boilerplate.utils.constrants.Security;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.i18n.AcceptHeaderLocaleResolver;

import io.swagger.v3.oas.models.OpenAPI;

import java.util.Locale;
import java.util.Properties;
import java.util.TimeZone;

@Configuration
public class AppConfig implements WebMvcConfigurer {

    @Bean
    public AcceptHeaderLocaleResolver localeResolver(@Value("${app.default-locale:en}") final String defaultLocale,
                                                     @Value("${app.default-timezone:UTC}") final String defaultTimezone) {
        AcceptHeaderLocaleResolver localResolver = new AcceptHeaderLocaleResolver();
        localResolver.setDefaultLocale(Locale.forLanguageTag(defaultLocale));
        TimeZone.setDefault(TimeZone.getTimeZone(defaultTimezone));

        return localResolver;
    }

//    @Bean
//    public JavaMailSender javaMailSender(@Value("${spring.mail.host}") String host,
//                                         @Value("${spring.mail.port}") int port,
//                                         @Value("${spring.mail.username}") String username,
//                                         @Value("${spring.mail.password}") String password) {
//
//        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
//        mailSender.setHost(host);
//        mailSender.setPort(port);
//        mailSender.setUsername(username);
//        mailSender.setPassword(password);
//
//        Properties props = mailSender.getJavaMailProperties();
//        props.put("mail.transport.protocol", "smtp");
//        props.put("mail.smtp.auth", "true");
//        props.put("mail.smtp.starttls.enable", "true");
//        props.put("mail.debug", "true");
//
//        return mailSender;
//    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public OpenAPI customOpenAPI(@Value("${spring.application.name}") String appName,
                                 @Value("${spring.application.description}") String appDesc,
                                 @Value("${spring.application.version}") String appVer) {
        return new OpenAPI()
                .addSecurityItem(new SecurityRequirement().addList(Security.BEARER_SCHEME))
                .components(new Components()
                        .addSecuritySchemes(Security.BEARER_SCHEME,
                                new SecurityScheme()
                                        .name("Authorization")
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT"))
                )
                .info(new Info().title(appName).version(appVer).description(appDesc)
                        .termsOfService("https:www.hunglorvike.com")
                        .license(new License().name("Apache 2.0")
                                .url("https://springdoc.org")));
    }

}
