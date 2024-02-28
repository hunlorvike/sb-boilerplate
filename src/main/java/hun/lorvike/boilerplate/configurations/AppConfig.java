package hun.lorvike.boilerplate.configurations;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.i18n.AcceptHeaderLocaleResolver;

import hun.lorvike.boilerplate.security.GetUserArgumentResolver;
import hun.lorvike.boilerplate.utils.constrant.Security;
import io.swagger.v3.oas.models.OpenAPI;

import java.util.List;
import java.util.Locale;
import java.util.TimeZone;

@Configuration
public class AppConfig implements WebMvcConfigurer {

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

	@Bean
    public OpenAPI customOpenAPI(@Value("${spring.application.name}") String appName,
            @Value("${spring.application.description}") String appDesc,
            @Value("${spring.application.version}") String appVer) {
        return new OpenAPI()
                .components(new Components()
                        .addSecuritySchemes(Security.BEARER_SCHEME, new SecurityScheme()
                                .name(Security.BEARER_SCHEME)
                                .type(SecurityScheme.Type.HTTP)
                                .scheme(Security.BEARER_SCHEME)
                                .bearerFormat("JWT")))
                .info(new Info().title(appName).version(appVer).description(appDesc)
                        .termsOfService("https:www.hunglorvike.com")
                        .license(new License().name("Apache 2.0")
                                .url("https://springdoc.org")));
    }
	@Override
	public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
		resolvers.add(new GetUserArgumentResolver());
	}

}
