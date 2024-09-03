package com.solana.com.mapper;

import com.solana.com.dto.IdeasDTO;
import com.solana.com.model.Ideas;
import org.mapstruct.Mapper;
import org.mapstruct.factory.Mappers;

@Mapper(componentModel = "spring")
public interface IdeasMapper {
    IdeasMapper INSTANCE = Mappers.getMapper(IdeasMapper.class);
    Ideas toIdeas(IdeasDTO ideasDTO);
    IdeasDTO toIdeasDto(Ideas ideas);
}
