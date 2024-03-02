package hun.lorvike.boilerplate.mappers;

import hun.lorvike.boilerplate.dtos.agency.AgencyDto;
import hun.lorvike.boilerplate.entities.Agency;
import org.mapstruct.*;
import org.mapstruct.factory.Mappers;

@Mapper(unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface IAgencyMapper {
    IAgencyMapper INSTANCE = Mappers.getMapper(IAgencyMapper.class);

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "agencyV4Id", ignore = true)
    @Mapping(target = "name", source = "name")
    @Mapping(target = "description", source = "description")
    @Mapping(target = "address", source = "address")
    @Mapping(target = "phoneNumber", source = "phoneNumber")
    @Mapping(target = "users", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "deleteAt", ignore = true)
    Agency toEntity(AgencyDto agencyDto);

    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    void updateEntityFromDto(AgencyDto agencyDto, @MappingTarget Agency agency);

}
