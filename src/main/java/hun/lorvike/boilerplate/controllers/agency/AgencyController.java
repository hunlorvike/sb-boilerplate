package hun.lorvike.boilerplate.controllers.agency;

import hun.lorvike.boilerplate.configurations.FormResponse;
import hun.lorvike.boilerplate.dtos.agency.AgencyDto;
import hun.lorvike.boilerplate.entities.Agency;
import hun.lorvike.boilerplate.services.IAgencyService;
import hun.lorvike.boilerplate.utils.constrants.Routes;
import hun.lorvike.boilerplate.utils.constrants.SwaggerTags;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping(Routes.AGENCY)
@Tag(name = SwaggerTags.AGENCY_TAG, description = "Agency API")
@FormResponse
public class AgencyController {

    private final IAgencyService agencyService;

    public AgencyController(IAgencyService agencyService) {
        this.agencyService = agencyService;
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('USER', 'MANAGER', 'ADMIN')")
    @Operation(
            summary = "Get all agencies",
            description = "Retrieve a list of all agencies with pagination.",
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successful operation",
                            content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = Agency.class))
                    ),
                    @ApiResponse(
                            responseCode = "422",
                            description = "Validation failed",
                            content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ErrorResponse.class))
                    )
            }
    )
    public List<Agency> getAllAgenciesAsync(
            @Parameter(description = "Page number (default is 0)")
            @RequestParam(name = "page", defaultValue = "0") int page,

            @Parameter(description = "Number of items per page (default is 10)")
            @RequestParam(name = "size", defaultValue = "10") int size) {
        return agencyService.getAllAgenciesAsync(page, size).join();
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('USER', 'MANAGER', 'ADMIN')")
    @Operation(
            summary = "Get agency by ID",
            description = "Retrieve an agency by its unique identifier.",
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successful operation",
                            content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = Agency.class))
                    ),
                    @ApiResponse(
                            responseCode = "404",
                            description = "Agency not found",
                            content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ErrorResponse.class))
                    )
            }
    )
    public Optional<Agency> getAgencyByIdAsync(
            @Parameter(description = "Unique identifier of the agency")
            @PathVariable Long id) {
        return agencyService.getAgencyByIdAsync(id).join();
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('USER', 'MANAGER', 'ADMIN')")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(
            summary = "Create a new agency",
            description = "Create a new agency with the provided details.",
            responses = {
                    @ApiResponse(
                            responseCode = "201",
                            description = "Successful creation",
                            content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = Agency.class))
                    ),
                    @ApiResponse(
                            responseCode = "422",
                            description = "Validation failed",
                            content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ErrorResponse.class))
                    )
            }
    )
    public Agency createAgencyAsync(
            @Parameter(description = "Agency details for creation")
            @Valid @RequestBody AgencyDto agencyDto) {
        return agencyService.createAgencyAsync(agencyDto).join();
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAnyRole('MANAGER', 'ADMIN')")
    @Operation(
            summary = "Update agency by ID",
            description = "Update an existing agency with the provided details.",
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successful update",
                            content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = Agency.class))
                    ),
                    @ApiResponse(
                            responseCode = "404",
                            description = "Agency not found",
                            content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ErrorResponse.class))
                    ),
                    @ApiResponse(
                            responseCode = "422",
                            description = "Validation failed",
                            content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ErrorResponse.class))
                    )
            }
    )
    public Agency updateAgencyAsync(
            @Parameter(description = "Unique identifier of the agency")
            @PathVariable Long id,

            @Parameter(description = "Updated agency details")
            @Valid @RequestBody AgencyDto agencyDto) {
        return agencyService.updateAgencyAsync(id, agencyDto).join();
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN')")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(
            summary = "Delete agency by ID",
            description = "Delete an existing agency by its unique identifier.",
            responses = {
                    @ApiResponse(
                            responseCode = "204",
                            description = "Successful deletion"
                    ),
                    @ApiResponse(
                            responseCode = "404",
                            description = "Agency not found",
                            content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ErrorResponse.class))
                    )
            }
    )
    public void deleteAgencyAsync(
            @Parameter(description = "Unique identifier of the agency")
            @PathVariable Long id) {
        agencyService.deleteAgencyAsync(id).join();
    }

    @GetMapping("/exists/{id}")
    @PreAuthorize("hasAnyRole('USER', 'MANAGER', 'ADMIN')")
    @Operation(
            summary = "Check if agency exists by ID",
            description = "Check if an agency with the given ID exists.",
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successful check",
                            content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = Boolean.class))
                    )
            }
    )
    public Boolean existsByIdAsync(
            @Parameter(description = "Unique identifier of the agency")
            @PathVariable Long id) {
        return agencyService.existsByIdAsync(id).join();
    }
}
