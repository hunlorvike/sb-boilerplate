package hun.lorvike.boilerplate.repositories;

import hun.lorvike.boilerplate.entities.Agency;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface IAgencyRepository extends CrudRepository<Agency, Long> {
}
