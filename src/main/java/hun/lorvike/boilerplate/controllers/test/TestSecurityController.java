package hun.lorvike.boilerplate.controllers.test;

import hun.lorvike.boilerplate.utils.constrants.Routes;
import hun.lorvike.boilerplate.utils.constrants.SwaggerTags;
import io.swagger.v3.oas.annotations.Operation;

import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;

@RestController
@Slf4j
@Tag(name = SwaggerTags.TEST_TAG, description = "Test API")
public class TestSecurityController {
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
