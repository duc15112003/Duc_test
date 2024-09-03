package com.solana.com.service;

import com.solana.com.dao.UsersRepository;
import com.solana.com.dto.UsersDTO;
import com.solana.com.mapper.UsersMapper;
import com.solana.com.model.Users;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

@Service
public class UsersService {
    @Autowired
    private UsersRepository usersRepository;

    public List<UsersDTO> getAllUsers() {
        List<Users> users = usersRepository.findAll();
        List<UsersDTO> usersDTOs = new ArrayList<UsersDTO>();
        for (Users user : users) {
            UsersDTO userDTO = UsersMapper.INSTANCE.toUsersDto(user);
            usersDTOs.add(userDTO);
        }
        return usersDTOs;
    }

    public UsersDTO getUserById(Long id) {
        Users users = usersRepository.findById(id).get();
        UsersDTO usersDTO = UsersMapper.INSTANCE.toUsersDto(users);
        return usersDTO;
    }

    public UsersDTO save(UsersDTO usersDTO) {
        Users user = UsersMapper.INSTANCE.toUsers(usersDTO);
        usersRepository.save(user);
        return usersDTO;
    }

    public UsersDTO update(UsersDTO usersDTO) {
        Users user = UsersMapper.INSTANCE.toUsers(usersDTO);
        user.setCreateAt(LocalDate.now());
        return UsersMapper.INSTANCE.toUsersDto(usersRepository.save(user));
    }

    public void delete(Long id) {
        usersRepository.deleteById(id);
    }

}
