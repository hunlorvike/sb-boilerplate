package hun.lorvike.boilerplate.controllers.auth;

import hun.lorvike.boilerplate.configurations.FormResponse;
import hun.lorvike.boilerplate.dtos.auth.LoginDto;
import hun.lorvike.boilerplate.dtos.auth.RegisterDto;
import hun.lorvike.boilerplate.dtos.auth.ResLoginDto;
import hun.lorvike.boilerplate.entities.User;
import hun.lorvike.boilerplate.security.IAuthService;
import hun.lorvike.boilerplate.utils.constrants.Routes;
import hun.lorvike.boilerplate.utils.constrants.SwaggerTags;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import io.swagger.v3.oas.annotations.tags.Tag;

@RestController
@RequiredArgsConstructor
@Tag(name = SwaggerTags.AUTH_TAG, description = "Auth API")
@FormResponse
@RequestMapping(Routes.AUTH)
public class AuthController {
    private final IAuthService iAuthService;

    @PostMapping("/register")
    @Operation(summary = "Register endpoint", responses = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Successful operation",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = User.class))),
            @ApiResponse(
                    responseCode = "422",
                    description = "Validation failed",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ErrorResponse.class)))
    })
    public User register(@Valid @RequestBody RegisterDto registerDto) {
        return iAuthService.registerUserAsync(registerDto).join();
    }

    @PostMapping("/login")
    @Operation(summary = "Login endpoint", responses = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Successful operation",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ResLoginDto.class))),
            @ApiResponse(
                    responseCode = "401",
                    description = "Unauthorized",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ErrorResponse.class)))
    })
    public ResLoginDto login(@Valid @RequestBody LoginDto loginDto) {
        return iAuthService.authenticateUserAsync(loginDto).join();
    }
}
