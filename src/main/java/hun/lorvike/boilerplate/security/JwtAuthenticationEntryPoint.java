package hun.lorvike.boilerplate.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

@Component
@Slf4j
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException) throws IOException {
        String errorMessage;

        String attribute = (String) request.getAttribute("attribute");
        if (attribute == null) {
            errorMessage = authException.getMessage();
        } else {
            switch (attribute) {
                case "expired" -> errorMessage = "Token has expired. Please log in again.";
                case "unsupported" -> errorMessage = "Unsupported token.";
                case "invalid", "illegal" -> errorMessage = "Invalid token.";
                case "notfound" -> errorMessage = "Token not found.";
                case "blocked" -> errorMessage = "Your account has been blocked.";
                case "disabled" -> errorMessage = "Your account has been disabled.";
                case "credentials_expired" -> errorMessage = "Password has expired. Please update your password.";
                case "account_locked" -> errorMessage = "Account locked. Please contact the administrator.";
                case "account_disabled" -> errorMessage = "Account disabled. Please contact the administrator.";
                default -> errorMessage = authException.getMessage();
            }
        }

        log.info(errorMessage);
        response.getWriter().write(errorMessage);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    }
}
