package hun.lorvike.boilerplate.configurations.filters;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;
import org.springframework.web.util.WebUtils;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.UUID;

@Component
@Slf4j
public class RequestLoggerFilter implements Filter {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        long startTime = System.currentTimeMillis();
        UUID uniqueId = UUID.randomUUID();
        MDC.put("requestId", uniqueId.toString());

        HttpServletRequest httpServletRequest = new ContentCachingRequestWrapper((HttpServletRequest) servletRequest);
        HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;

        log.info("Received request [{} {}] from IP address {}", httpServletRequest.getMethod(), httpServletRequest.getRequestURI(), httpServletRequest.getRemoteAddr());
        log.info("Request content type is {}", httpServletRequest.getContentType());

        String requestBody = getRequestBody(httpServletRequest);
        if (requestBody != null) {
            log.info("Request payload: {}", requestBody);
        }

        ContentCachingResponseWrapper responseWrapper = new ContentCachingResponseWrapper(httpServletResponse);

        try {
            filterChain.doFilter(httpServletRequest, responseWrapper);
        } finally {
            log.info("Response status: {}", responseWrapper.getStatus());
            log.info("Response time: {} ms", System.currentTimeMillis() - startTime);

            responseWrapper.setHeader("requestId", uniqueId.toString());
            responseWrapper.copyBodyToResponse();
            log.info("Response header is set with uuid {}", responseWrapper.getHeader("requestId"));

            MDC.clear();
        }
    }

    private String getRequestBody(HttpServletRequest request) {
        ContentCachingRequestWrapper wrapper = WebUtils.getNativeRequest(request, ContentCachingRequestWrapper.class);
        if (wrapper != null) {
            byte[] buf = wrapper.getContentAsByteArray();
            if (buf.length > 0) {
                try {
                    return new String(buf, 0, buf.length, wrapper.getCharacterEncoding());
                } catch (UnsupportedEncodingException e) {
                    log.error("Error reading request body", e);
                }
            }
        }
        return null;
    }
}
