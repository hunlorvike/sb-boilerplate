package hun.lorvike.boilerplate.configurations;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;


@Configuration
@RestControllerAdvice(annotations = ApiResponse.class)
public class CustomResponseBodyAdvice implements ResponseBodyAdvice<Object> {
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    static class ApiResponse<T> {
        private int code;
        private T data;
    }

    @Override
    public boolean supports(@NonNull MethodParameter returnType, @NonNull Class<? extends HttpMessageConverter<?>> converterType) {
        return true;
    }

    @Override
    public Object beforeBodyWrite(Object body, @NonNull MethodParameter returnType, @Nullable MediaType selectedContentType,
                                  @Nullable Class<? extends HttpMessageConverter<?>> selectedConverterType,
                                  @Nullable ServerHttpRequest request, @Nullable ServerHttpResponse response) {
        try {
            if (body != null && !(body instanceof Exception)) {
                return new ApiResponse<>(200, body);
            }
            return body;

        } catch (Exception e) {
            return new ApiResponse<>(500, "Internal Server Error");
        }
    }
}
