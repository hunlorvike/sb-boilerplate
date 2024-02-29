package hun.lorvike.boilerplate.controllers.test;

import hun.lorvike.boilerplate.entities.User;
import hun.lorvike.boilerplate.utils.constrants.Routes;
import hun.lorvike.boilerplate.utils.constrants.SwaggerTags;
import io.swagger.v3.oas.annotations.Operation;

import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.server.ResponseStatusException;

@RestController
@Slf4j
@Tag(name = SwaggerTags.TEST_TAG, description = "Test API")
public class TestSecurityController {
    @GetMapping(Routes.ME)
    public User getUser(HttpServletRequest request) {
        User user = (User) request.getAttribute("user");

        if (user != null) {
            return user;
        } else {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found");
        }
    }

    @Operation(summary = "Check if user has ROLE_USER", description = "Check if the authenticated user has the role USER.")
    @GetMapping(Routes.ROLE_USER)
    @PreAuthorize("hasRole('USER')")
    public String getUserRoleTest() {
        log.info("User has ROLE_USER");
        return "User has ROLE_USER";
    }

    @Operation(summary = "Check if user has ROLE_MANAGER", description = "Check if the authenticated user has the role MANAGER.")
    @GetMapping(Routes.ROLE_MANAGER)
    @PreAuthorize("hasRole('MANAGER')")
    public String getManagerRoleTest() {
        log.info("User has ROLE_MANAGER");
        return "User has ROLE_MANAGER";
    }

    @Operation(summary = "Check if user has ROLE_ADMIN", description = "Check if the authenticated user has the role ADMIN.")
    @DeleteMapping(Routes.ROLE_ADMIN)
    @PreAuthorize("hasRole('ADMIN')")
    public String getAdminRoleTest() {
        log.info("User has ROLE_ADMIN");
        return "User has ROLE_ADMIN";
    }
}
