package hun.lorvike.boilerplate.dtos.auth;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.*;
import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RegisterDto {

    @NotBlank(message = "Name is required")
    @Schema(description = "User's name", example = "John Doe")
    private String name;

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    @Schema(description = "User's email address", example = "john@example.com")
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 6, message = "Password must be at least 6 characters")
    @Schema(description = "User's password", example = "strongPassword")
    private String password;
}

