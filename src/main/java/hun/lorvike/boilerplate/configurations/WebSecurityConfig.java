package hun.lorvike.boilerplate.configurations;

import hun.lorvike.boilerplate.security.AuthenticationFilter;
import hun.lorvike.boilerplate.security.JwtAuthenticationEntryPoint;
import hun.lorvike.boilerplate.utils.enums.ERole;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
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
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
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
            "/swagger-ui/index.html",
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
                .authenticationProvider(authenticationProvider())
                .authorizeHttpRequests(request -> request
                        .requestMatchers(HttpMethod.GET, PUBLIC_URLS).permitAll()
                        .requestMatchers(PUBLIC_URLS).permitAll()
                        .requestMatchers(PRIVATE_URLS).hasAnyRole("ADMIN")
                        .requestMatchers(HttpMethod.GET, PRIVATE_URLS).hasAnyRole("MANAGER")
                        .requestMatchers(HttpMethod.POST, PRIVATE_URLS).hasAnyRole("MANAGER")
                        .requestMatchers(HttpMethod.PUT, PRIVATE_URLS).hasAnyRole("MANAGER")
                        .requestMatchers(HttpMethod.DELETE, PRIVATE_URLS).hasAnyRole("ADMIN")
                        .anyRequest().authenticated())
                .addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .formLogin(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults())
                .logout(Customizer.withDefaults())
                .exceptionHandling(config -> config
                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
                        .accessDeniedHandler(accessDeniedHandler()))
                .build();
    }

    private AccessDeniedHandler accessDeniedHandler() {
        return (request, response, accessDeniedException) -> {
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.getWriter().write("Access denied. You don't have the required role.");
        };
    }

}
