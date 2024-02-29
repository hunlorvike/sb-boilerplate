package hun.lorvike.boilerplate.configurations;
import org.springframework.core.annotation.AliasFor;
import org.springframework.web.bind.annotation.ModelAttribute;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
public @interface GetRequestAttribute {
    @AliasFor(annotation = ModelAttribute.class)
    String value() default "";
}
