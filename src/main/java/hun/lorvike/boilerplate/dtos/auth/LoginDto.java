package hun.lorvike.boilerplate.dtos.auth;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginDto {
    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    @Schema(description = "User's email address", example = "john@example.com")
    private String email;

    @NotBlank(message = "Password is required")
    @Schema(description = "User's password", example = "strongPassword")
    private String password;
}
