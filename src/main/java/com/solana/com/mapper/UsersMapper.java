package com.solana.com.mapper;

import com.solana.com.dto.UsersDTO;
import com.solana.com.model.Users;
import org.mapstruct.Mapper;
import org.mapstruct.factory.Mappers;

@Mapper(componentModel = "spring")
public interface UsersMapper {
    UsersMapper INSTANCE = Mappers.getMapper(UsersMapper.class);
    Users toUsers(UsersDTO usersDTO);
    UsersDTO toUsersDto(Users users);
}
