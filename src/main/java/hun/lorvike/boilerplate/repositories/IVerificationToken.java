package hun.lorvike.boilerplate.repositories;

import hun.lorvike.boilerplate.entities.VerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface IVerificationToken extends JpaRepository<VerificationToken, Long> {
}
