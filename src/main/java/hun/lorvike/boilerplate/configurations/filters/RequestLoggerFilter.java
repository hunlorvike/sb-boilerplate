package hun.lorvike.boilerplate.configurations.filters;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.UUID;

@Component
@Slf4j
public class RequestLoggerFilter implements Filter {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        long startTime = System.currentTimeMillis();
        UUID uniqueId = UUID.randomUUID();
        MDC.put("requestId", uniqueId.toString());

        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;

        log.info("Received request [{} {}] from IP address {}", httpServletRequest.getMethod(), httpServletRequest.getRequestURI(), httpServletRequest.getRemoteAddr());
        log.info("Request content type is {}", httpServletRequest.getContentType());

        log.info("Request payload: {}", getRequestBody(httpServletRequest));

        ContentCachingResponseWrapper responseWrapper = new ContentCachingResponseWrapper(httpServletResponse);

        filterChain.doFilter(servletRequest, responseWrapper);

        log.info("Response status: {}", responseWrapper.getStatus());
        log.info("Response time: {} ms", System.currentTimeMillis() - startTime);

        responseWrapper.setHeader("requestId", uniqueId.toString());
        responseWrapper.copyBodyToResponse();
        log.info("Response header is set with uuid {}", responseWrapper.getHeader("requestId"));

        MDC.clear();
    }

    private String getRequestBody(HttpServletRequest request) throws IOException {
        StringBuilder stringBuilder = new StringBuilder();
        try (BufferedReader bufferedReader = request.getReader()) {
            char[] charBuffer = new char[1024];
            int bytesRead;
            while ((bytesRead = bufferedReader.read(charBuffer)) != -1) {
                stringBuilder.append(charBuffer, 0, bytesRead);
            }
        }
        return stringBuilder.toString();
    }
}
