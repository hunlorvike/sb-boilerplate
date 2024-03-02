package hun.lorvike.boilerplate.services.impls;

import hun.lorvike.boilerplate.dtos.agency.AgencyDto;
import hun.lorvike.boilerplate.entities.Agency;
import hun.lorvike.boilerplate.mappers.IAgencyMapper;
import hun.lorvike.boilerplate.repositories.IAgencyRepository;
import hun.lorvike.boilerplate.services.IAgencyService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

@Service
@RequiredArgsConstructor
public class AgencyServiceImpl implements IAgencyService {

    private final IAgencyRepository agencyRepository;

    @Override
    @Transactional(readOnly = true)
    public CompletableFuture<List<Agency>> getAllAgenciesAsync() {
        return CompletableFuture.supplyAsync(() -> agencyRepository.findAll()
                .stream()
                .filter(agency -> agency.getDeleteAt() == null)
                .toList());
    }

    @Override
    @Transactional(readOnly = true)
    public CompletableFuture<List<Agency>> getAllAgenciesAsync(int page, int size) {
        return CompletableFuture.supplyAsync(() -> {
            Pageable pageable = PageRequest.of(page, size);
            return agencyRepository.findAll(pageable)
                    .getContent()
                    .stream()
                    .filter(agency -> agency.getDeleteAt() == null)
                    .toList();
        });
    }

    @Override
    @Transactional(readOnly = true)
    public CompletableFuture<Optional<Agency>> getAgencyByIdAsync(Long id) {
        return CompletableFuture.supplyAsync(() ->
                agencyRepository.findAll()
                        .stream()
                        .filter(agency -> agency.getId().equals(id) && agency.getDeleteAt() == null)
                        .findFirst()
        );
    }

    @Override
    @Transactional()
    public CompletableFuture<Agency> createAgencyAsync(AgencyDto agencyDto) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                Agency agency = IAgencyMapper.INSTANCE.toEntity(agencyDto);
                agency.setAgencyV4Id(UUID.randomUUID());
                return agencyRepository.save(agency);
            } catch (Exception e) {
                throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Error creating agency", e);
            }
        });
    }

    @Override
    @Transactional()
    public CompletableFuture<Agency> updateAgencyAsync(Long id, AgencyDto agencyDto) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                Optional<Agency> existingAgency = agencyRepository.findByIdAndDeleteAtIsNull(id);
                if (existingAgency.isEmpty()) {
                    throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Agency not found with id: " + id);
                }

                IAgencyMapper.INSTANCE.updateEntityFromDto(agencyDto, existingAgency.get());
                existingAgency.get().setUpdatedAt(LocalDateTime.now());

                return agencyRepository.save(existingAgency.get());
            } catch (Exception e) {
                throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Error updating agency", e);
            }
        });
    }


    @Override
    @Transactional()
    public CompletableFuture<Void> deleteAgencyAsync(Long id) {
        return CompletableFuture.runAsync(() -> {
            try {
                Optional<Agency> existingAgency = agencyRepository.findByIdAndDeleteAtIsNull(id);
                if (existingAgency.isEmpty()) {
                    throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Agency not found with id: " + id);
                }

                Agency deletedAgency = existingAgency.get();
                deletedAgency.setDeleteAt(LocalDateTime.now());
                agencyRepository.save(deletedAgency);
            } catch (Exception e) {
                throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Error deleting agency", e);
            }
        });
    }

    @Override
    @Transactional()
    public CompletableFuture<Boolean> existsByIdAsync(Long id) {
        return CompletableFuture.supplyAsync(() ->
                agencyRepository.findAll()
                        .stream()
                        .anyMatch(agency -> agency.getId().equals(id) && agency.getDeleteAt() == null)
        );
    }

}

