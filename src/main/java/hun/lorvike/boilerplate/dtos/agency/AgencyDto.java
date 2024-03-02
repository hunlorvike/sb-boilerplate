package hun.lorvike.boilerplate.dtos.agency;

import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AgencyDto {

    @NotBlank(message = "Name cannot be blank")
    @Schema(description = "Agency name", example = "ABC Agency")
    private String name;

    @Size(max = 255, message = "Description cannot exceed 255 characters")
    @Schema(description = "Agency description", example = "A leading agency in the industry")
    private String description;

    @NotBlank(message = "Address cannot be blank")
    @Schema(description = "Agency address", example = "123 Main Street")
    private String address;

    @Size(min = 10, max = 15, message = "Phone number must be between 10 and 15 characters")
    @Schema(description = "Agency phone number", example = "1234567890")
    private String phoneNumber;
}
