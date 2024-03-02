package hun.lorvike.boilerplate.services;

import hun.lorvike.boilerplate.dtos.agency.AgencyDto;
import hun.lorvike.boilerplate.entities.Agency;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

public interface IAgencyService {

    CompletableFuture<List<Agency>> getAllAgenciesAsync();

    CompletableFuture<List<Agency>> getAllAgenciesAsync(int page, int size);

    CompletableFuture<Optional<Agency>> getAgencyByIdAsync(Long id);

    CompletableFuture<Agency> createAgencyAsync(AgencyDto agencyDto);

    CompletableFuture<Agency> updateAgencyAsync(Long id, AgencyDto agencyDto);

    CompletableFuture<Void> deleteAgencyAsync(Long id);

    CompletableFuture<Boolean> existsByIdAsync(Long id);
}
