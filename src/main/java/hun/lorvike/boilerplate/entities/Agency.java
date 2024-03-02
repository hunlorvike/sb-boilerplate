package hun.lorvike.boilerplate.entities;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "agencies")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Agency {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private UUID agencyV4Id;

    private String name;

    private String description;

    private String address;

    private String phoneNumber;

    @OneToMany(mappedBy = "agency", cascade = CascadeType.ALL)
    private List<User> users = new ArrayList<>();

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @Column(name = "delete_at", nullable = true)
    private LocalDateTime deleteAt;
}
