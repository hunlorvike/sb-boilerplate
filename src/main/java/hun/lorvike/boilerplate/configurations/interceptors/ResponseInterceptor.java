package hun.lorvike.boilerplate.configurations.interceptors;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;

@Data
@NoArgsConstructor
@AllArgsConstructor
class ApiResponse {
    private String code;
    private Object data;
}

@Component
@Slf4j
public class ResponseInterceptor implements HandlerInterceptor {
    private final ObjectMapper objectMapper;

    public ResponseInterceptor(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    private void sendErrorResponse(HttpServletResponse response, String errorCode, String errorMessage, int statusCode)
            throws IOException {
        ApiResponse apiResponse = new ApiResponse(errorCode, errorMessage);
        response.setStatus(statusCode);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(objectMapper.writeValueAsString(apiResponse));
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        log.info("--------------------------------------");
        log.info("Interceptor is called");
        log.info("--------------------------------------");
        return true;
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler,
            ModelAndView modelAndView) throws Exception {
        log.info("Post-handle: Intercepting response");
        if (response.getStatus() == HttpServletResponse.SC_UNAUTHORIZED) {
            sendErrorResponse(response, "UNAUTHORIZED", "Unauthorized access", HttpServletResponse.SC_UNAUTHORIZED);
        }
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex)
            throws Exception {
        log.info("After completion: Request completed");
    }
}
