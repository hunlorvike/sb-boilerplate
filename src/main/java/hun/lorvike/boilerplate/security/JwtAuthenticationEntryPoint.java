package hun.lorvike.boilerplate.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

@Component
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
                case "expired" -> errorMessage = "Token hết hạn. Vui lòng đăng nhập lại.";
                case "unsupported" -> errorMessage = "Token không được hỗ trợ.";
                case "invalid", "illegal" -> errorMessage = "Token không hợp lệ.";
                case "notfound" -> errorMessage = "Token không tồn tại.";
                case "blocked" -> errorMessage = "Tài khoản của bạn đã bị khóa.";
                case "disabled" -> errorMessage = "Tài khoản của bạn đã bị vô hiệu hóa.";
                default -> errorMessage = authException.getMessage();
            }
        }

        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, errorMessage);
    }
}
