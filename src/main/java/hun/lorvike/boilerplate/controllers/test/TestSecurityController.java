package hun.lorvike.boilerplate.controllers.test;

import org.springframework.web.bind.annotation.RestController;

import hun.lorvike.boilerplate.entities.User;
import hun.lorvike.boilerplate.security.GetUser;
import hun.lorvike.boilerplate.utils.constrant.Routes;
import lombok.extern.slf4j.Slf4j;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;

@RestController
@Slf4j
public class TestSecurityController {
    @GetMapping(Routes.ME)
    public User getMethodName(@GetUser User user) {
        log.info("User Information: ", user);
        return user;
    }

    @GetMapping(Routes.ROLE_USER)
    @PreAuthorize("hasRole('USER')")
    public String getUserRoleTest() {
        log.info("User has ROLE_USER");
        return "User has ROLE_USER";
    }

    @GetMapping(Routes.ROLE_MANAGER)
    @PreAuthorize("hasRole('MANAGER')")
    public String getManagerRoleTest() {
        log.info("User has ROLE_MANAGER");
        return "User has ROLE_MANAGER";
    }

    @GetMapping(Routes.ROLE_ADMIN)
    @PreAuthorize("hasRole('ADMIN')")
    public String getAdminRoleTest() {
        log.info("User has ROLE_ADMIN");
        return "User has ROLE_ADMIN";
    }

}
