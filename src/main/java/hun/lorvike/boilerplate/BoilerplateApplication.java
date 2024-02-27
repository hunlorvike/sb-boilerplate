package hun.lorvike.boilerplate;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class BoilerplateApplication {

    public static void main(String[] args) {
        SpringApplication.run(BoilerplateApplication.class, args);
    }

    @GetMapping("")
    public String hello() {
        return "Hello World";
    }

    @GetMapping("/admin/")
    public String helloAdmin() {
        return "Hello Admin";
    }

//    @Bean
//    public ApplicationListener<ApplicationReadyEvent> readyListener() {
//        return applicationReadyEvent -> {
//            System.out.println("Application is ready, listing all beans:");
//            String[] beans = applicationReadyEvent.getApplicationContext().getBeanDefinitionNames();
//            for (String bean : beans) {
//                System.out.println(bean);
//            }
//        };
//    }

}
