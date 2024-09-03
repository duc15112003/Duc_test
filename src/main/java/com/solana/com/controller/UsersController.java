package com.solana.com.controller;

import com.solana.com.dto.UsersDTO;
import com.solana.com.service.UsersService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
//@CrossOrigin(origins = "http://localhost:8081")
public class UsersController {

    private final UsersService usersService;

    @GetMapping
    public ResponseEntity<List<UsersDTO>> getAllUsers() {
        return ResponseEntity.ok(usersService.getAllUsers());
    }

    @PostMapping
    public ResponseEntity<UsersDTO> createUser(@RequestBody UsersDTO usersDTO) {
        return ResponseEntity.status(HttpStatus.CREATED).body(usersService.save(usersDTO));
    }

    @PutMapping
    public ResponseEntity<UsersDTO> updateUser(@RequestBody UsersDTO usersDTO) {
        return ResponseEntity.ok(usersService.update(usersDTO));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        usersService.delete(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/{id}")
    public ResponseEntity<UsersDTO> getUser(@PathVariable Long id) {
        UsersDTO usersDTO = usersService.getUserById(id);
        return ResponseEntity.ok(usersDTO);
    }

}
