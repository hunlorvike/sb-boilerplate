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

import java.io.BufferedReader;
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

        log.info("Request payload: {}", getRequestBody(httpServletRequest));

        ContentCachingResponseWrapper responseWrapper = new ContentCachingResponseWrapper(httpServletResponse);

        filterChain.doFilter(httpServletRequest, responseWrapper);

        log.info("Response status: {}", responseWrapper.getStatus());
        log.info("Response time: {} ms", System.currentTimeMillis() - startTime);

        responseWrapper.setHeader("requestId", uniqueId.toString());
        responseWrapper.copyBodyToResponse();
        log.info("Response header is set with uuid {}", responseWrapper.getHeader("requestId"));

        MDC.clear();
    }

    private String getRequestBody(HttpServletRequest request) throws UnsupportedEncodingException {
        ContentCachingRequestWrapper wrapper = WebUtils.getNativeRequest(request, ContentCachingRequestWrapper.class);
        if (wrapper != null) {
            byte[] buf = wrapper.getContentAsByteArray();
            if (buf.length > 0) {
                return new String(buf, 0, buf.length, wrapper.getCharacterEncoding());
            }
        }
        return "";
    }
}
