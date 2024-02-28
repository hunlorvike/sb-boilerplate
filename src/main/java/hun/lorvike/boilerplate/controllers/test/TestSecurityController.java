package hun.lorvike.boilerplate.controllers.test;

import hun.lorvike.boilerplate.utils.constrants.Routes;
import hun.lorvike.boilerplate.utils.constrants.Tags;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.security.OAuthFlows;
import io.swagger.v3.oas.annotations.security.OAuthFlow;
import io.swagger.v3.oas.annotations.security.OAuthScope;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import hun.lorvike.boilerplate.entities.User;
import hun.lorvike.boilerplate.security.GetUser;
import lombok.extern.slf4j.Slf4j;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;

@RestController
@Slf4j
@Tag(name = Tags.TEST_TAG, description = "Test API")
@SecurityScheme(
        name = "bearerAuth",
        type = SecuritySchemeType.OAUTH2,
        bearerFormat = "JWT",
        scheme = "bearer",
        flows = @OAuthFlows(
                authorizationCode = @OAuthFlow(
                        authorizationUrl = "/auth/authorize",
                        tokenUrl = "/auth/token",
                        scopes = {
                                @OAuthScope(name = "read", description = "Read access"),
                                @OAuthScope(name = "write", description = "Write access")
                        }
                )
        )
)
@SecurityRequirement(
        name = "bearerAuth",
        scopes = {"read", "write"}
)

public class TestSecurityController {

    @Operation(summary = "Get user information", description = "Retrieve information about the authenticated user.")
    @GetMapping(Routes.ME)
    public User getMethodName(@GetUser User user) {
        log.info("User Information: {}", user);
        return user;
    }

    @Operation(summary = "Check if user has ROLE_USER", description = "Check if the authenticated user has the role USER.")
    @PostMapping(Routes.ROLE_USER)
    @PreAuthorize("hasAnyAuthority('ROLE_USER')")
    public String getUserRoleTest() {
        log.info("User has ROLE_USER");
        return "User has ROLE_USER";
    }

    @Operation(summary = "Check if user has ROLE_MANAGER", description = "Check if the authenticated user has the role MANAGER.")
    @PostMapping(Routes.ROLE_MANAGER)
    @PreAuthorize("hasAnyAuthority('ROLE_MANAGER')")
    public String getManagerRoleTest() {
        log.info("User has ROLE_MANAGER");
        return "User has ROLE_MANAGER";
    }

    @Operation(summary = "Check if user has ROLE_ADMIN", description = "Check if the authenticated user has the role ADMIN.")
    @PostMapping(Routes.ROLE_ADMIN)
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN')")
    public String getAdminRoleTest() {
        log.info("User has ROLE_ADMIN");
        return "User has ROLE_ADMIN";
    }
}
