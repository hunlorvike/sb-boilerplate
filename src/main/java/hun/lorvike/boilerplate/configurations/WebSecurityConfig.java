package hun.lorvike.boilerplate.configurations;


import hun.lorvike.boilerplate.configurations.enums.ERole;
import hun.lorvike.boilerplate.security.AuthenticationFilter;
import hun.lorvike.boilerplate.security.JwtAuthenticationEntryPoint;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
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
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
@Slf4j
public class WebSecurityConfig {
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    private final AuthenticationFilter authenticationFilter;

    private final UserDetailsService userDetailsService;

    private final PasswordEncoder passwordEncoder;

    private static final String[] PUBLIC_URLS = {
            "/public/**",
    };

    private static final String[] PRIVATE_URLS = {
            "/private/**",
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
                .sessionManagement(config -> config.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .headers(config -> config.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
                .addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(request ->
                        request.requestMatchers("/").permitAll()
                                .requestMatchers(HttpMethod.GET, PUBLIC_URLS).permitAll()
                                .requestMatchers(PUBLIC_URLS).permitAll()
                                .requestMatchers(PRIVATE_URLS).hasAnyRole(ERole.ADMIN.name())
                                .requestMatchers(HttpMethod.POST, PRIVATE_URLS).hasAnyRole(ERole.MANAGER.name())
                                .requestMatchers(HttpMethod.PUT, PRIVATE_URLS).hasAnyRole(ERole.MANAGER.name())
                                .requestMatchers(HttpMethod.PATCH, PRIVATE_URLS).hasAnyRole(ERole.MANAGER.name())
                                .requestMatchers(HttpMethod.DELETE, PRIVATE_URLS).hasAnyRole(ERole.ADMIN.name())
                                .anyRequest().authenticated())
                .authenticationProvider(authenticationProvider())
                .exceptionHandling(config -> config.accessDeniedHandler(new AccessDeniedHandler() {
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        log.error("Access denied. You don't have the required role.");
                        response.setStatus(HttpStatus.FORBIDDEN.value());
                        response.getWriter().write("Access denied. You don't have the required role.");
                    }
                }))
                .build();
    }

}
