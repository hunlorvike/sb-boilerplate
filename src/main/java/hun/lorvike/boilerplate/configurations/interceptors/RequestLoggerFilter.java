package hun.lorvike.boilerplate.configurations.interceptors;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.io.IOException;
import java.util.UUID;

@Component
@Slf4j
public class RequestLoggerFilter implements Filter {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        UUID uniqueId = UUID.randomUUID();
        MDC.put("requestId", uniqueId.toString());
        log.info("Request IP address is {}", servletRequest.getRemoteAddr());
        log.info("Request content type is {}", servletRequest.getContentType());
        HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;
        ContentCachingResponseWrapper responseWrapper = new ContentCachingResponseWrapper(
                httpServletResponse
        );
        filterChain.doFilter(servletRequest, responseWrapper);
        responseWrapper.setHeader("requestId", uniqueId.toString());
        responseWrapper.copyBodyToResponse();
        log.info("Response header is set with uuid {}", responseWrapper.getHeader("requestId"));
    }
    
}
