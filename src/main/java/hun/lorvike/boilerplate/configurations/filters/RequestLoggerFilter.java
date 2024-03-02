package hun.lorvike.boilerplate.configurations.filters;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

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

        HttpServletRequest request = (HttpServletRequest) servletRequest;
        ContentCachingRequestWrapper requestWrapper = new ContentCachingRequestWrapper(request);

        ContentCachingResponseWrapper responseWrapper = new ContentCachingResponseWrapper((HttpServletResponse) servletResponse);

<<<<<<< HEAD
        try {
            filterChain.doFilter(requestWrapper, responseWrapper);
        } finally {
            log.info("Received request [{} {}] from IP address {}", request.getMethod(), request.getRequestURI(), request.getRemoteAddr());
            log.info("Request content type is {}", requestWrapper.getContentType());
=======
        String requestBody = getRequestBody(httpServletRequest);
        if (requestBody != null) {
            log.info("Request payload: {}", requestBody);
        }
>>>>>>> 22acfaa4cdb0d5f0597cb69081d70d53a4efe2c1

            String requestBody = getRequestBody(requestWrapper);
            if (requestBody != null) {
                log.info("Request payload: {}", requestBody);
            }

<<<<<<< HEAD
            log.info("Response status: {}", responseWrapper.getStatus());
            log.info("Response time: {} ms", System.currentTimeMillis() - startTime);

            String responseBody = getResponseBody(responseWrapper);
            if (responseBody != null) {
                log.info("Response payload: {}", responseBody);
            }

            responseWrapper.copyBodyToResponse();
=======
        try {
            filterChain.doFilter(httpServletRequest, responseWrapper);
        } finally {
            log.info("Response status: {}", responseWrapper.getStatus());
            log.info("Response time: {} ms", System.currentTimeMillis() - startTime);

            responseWrapper.setHeader("requestId", uniqueId.toString());
            responseWrapper.copyBodyToResponse();
            log.info("Response header is set with uuid {}", responseWrapper.getHeader("requestId"));

>>>>>>> 22acfaa4cdb0d5f0597cb69081d70d53a4efe2c1
            MDC.clear();
        }
    }

<<<<<<< HEAD
    private String getRequestBody(ContentCachingRequestWrapper requestWrapper) {
        byte[] buf = requestWrapper.getContentAsByteArray();
        if (buf.length > 0) {
            try {
                return new String(buf, requestWrapper.getCharacterEncoding());
            } catch (UnsupportedEncodingException e) {
                log.error("Error reading request body", e);
            }
        }
        return null;
    }

    private String getResponseBody(ContentCachingResponseWrapper responseWrapper) {
        byte[] buf = responseWrapper.getContentAsByteArray();
        if (buf.length > 0) {
            try {
                return new String(buf, responseWrapper.getCharacterEncoding());
            } catch (UnsupportedEncodingException e) {
                log.error("Error reading response body", e);
            }
        }
        return null;
=======
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
>>>>>>> 22acfaa4cdb0d5f0597cb69081d70d53a4efe2c1
    }
}
