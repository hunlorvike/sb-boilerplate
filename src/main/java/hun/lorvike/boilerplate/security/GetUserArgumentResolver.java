package hun.lorvike.boilerplate.security;

import org.springframework.core.MethodParameter;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;
import org.springframework.lang.Nullable;

import hun.lorvike.boilerplate.entities.User;

public class GetUserArgumentResolver implements HandlerMethodArgumentResolver {

    @Override
    public Object resolveArgument(MethodParameter parameter, @Nullable ModelAndViewContainer modelAndViewContainer,
            NativeWebRequest webRequest, @Nullable WebDataBinderFactory webDataBinderFactory) throws Exception {
        User user = (User) webRequest.getAttribute("user", NativeWebRequest.SCOPE_REQUEST);

        if (user != null) {
            return user;
        } else {
            throw new RuntimeException("User not authenticated");
        }
    }

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.getParameterAnnotation(GetUser.class) != null &&
                parameter.getParameterType().equals(User.class);
    }
}
