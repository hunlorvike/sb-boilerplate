package hun.lorvike.boilerplate;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;


@SpringBootApplication
public class BoilerplateApplication {

    public static void main(String[] args) {
        SpringApplication.run(BoilerplateApplication.class, args);
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
