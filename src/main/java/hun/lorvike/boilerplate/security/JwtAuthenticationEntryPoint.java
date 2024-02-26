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
        String errorMessage = null;

        String attribute = (String) request.getAttribute("attribute");

        switch (attribute) {
            case "expired":
                errorMessage = "Token hết hạn. Vui lòng đăng nhập lại.";
                break;
            case "unsupported":
                errorMessage = "Token không được hỗ trợ.";
                break;
            case "invalid":
            case "illegal":
                errorMessage = "Token không hợp lệ.";
                break;
            case "notfound":
                errorMessage = "Token không tồn tại.";
                break;
            case "blocked":
                errorMessage = "Tài khoản của bạn đã bị khóa.";
                break;
            case "disabled":
                errorMessage = "Tài khoản của bạn đã bị vô hiệu hóa.";
                break;
            default:
                errorMessage = authException.getMessage();
        }

        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, errorMessage);
    }
}
