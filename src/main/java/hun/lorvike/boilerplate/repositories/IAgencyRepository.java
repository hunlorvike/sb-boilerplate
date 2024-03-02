package hun.lorvike.boilerplate.repositories;

import hun.lorvike.boilerplate.entities.Agency;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface IAgencyRepository extends JpaRepository<Agency, Long> {

    Optional<Agency> findByIdAndDeleteAtIsNull(Long id);
}
