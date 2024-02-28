package hun.lorvike.boilerplate.configurations;

import hun.lorvike.boilerplate.configurations.enums.ERole;
import hun.lorvike.boilerplate.security.AuthenticationFilter;
import hun.lorvike.boilerplate.security.JwtAuthenticationEntryPoint;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class WebSecurityConfig {
	private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

	private final AuthenticationFilter authenticationFilter;

	private final UserDetailsService userDetailsService;

	private final PasswordEncoder passwordEncoder;

	private static final String[] PUBLIC_URLS = {
			"/",
			"/api/auth/**",
			"/public/**",
			"/assets/**",
			"/api-docs/**",
			"/swagger-ui/**",
			"/webjars/**",
			"/ws/**"
	};

	private static final String[] PRIVATE_URLS = {
			"/admin/**",
	};

	private AuthenticationProvider authenticationProvider() {
		final DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
		authenticationProvider.setUserDetailsService(userDetailsService);
		authenticationProvider.setPasswordEncoder(passwordEncoder);
		return authenticationProvider;
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
		return httpSecurity
				.cors(Customizer.withDefaults())
				.csrf(AbstractHttpConfigurer::disable)
				.sessionManagement(
						config -> config.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.headers(config -> config.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
				.addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class)
				.authorizeHttpRequests(request -> request.requestMatchers(HttpMethod.GET, PUBLIC_URLS)
						.permitAll()
						.requestMatchers(PUBLIC_URLS).permitAll()
						.requestMatchers(PRIVATE_URLS).hasAnyRole(ERole.ADMIN.name())
						.requestMatchers(HttpMethod.POST, PRIVATE_URLS)
						.hasAnyRole(ERole.MANAGER.name())
						.requestMatchers(HttpMethod.PUT, PRIVATE_URLS)
						.hasAnyRole(ERole.MANAGER.name())
						.requestMatchers(HttpMethod.PATCH, PRIVATE_URLS)
						.hasAnyRole(ERole.MANAGER.name())
						.requestMatchers(HttpMethod.DELETE, PRIVATE_URLS)
						.hasAnyRole(ERole.ADMIN.name())
						.anyRequest().authenticated())
				.formLogin(Customizer.withDefaults())
				.authenticationProvider(authenticationProvider())
				.exceptionHandling(
						config -> config.authenticationEntryPoint(jwtAuthenticationEntryPoint))
				.build();
	}

}
