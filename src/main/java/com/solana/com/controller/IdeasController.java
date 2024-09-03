package com.solana.com.controller;

import com.solana.com.dto.IdeasDTO;
import com.solana.com.model.Ideas;
import com.solana.com.service.IdeasService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/ideas")
@RequiredArgsConstructor
//@CrossOrigin(origins = "http://localhost:8081")
public class IdeasController {

    private final IdeasService service;

    @GetMapping
    public ResponseEntity<List<Ideas>> getAllIdeas(){
        return ResponseEntity.ok(service.findAll());
    }

    @PostMapping
    public ResponseEntity<Ideas> createIdeas(@RequestBody IdeasDTO ideasDTO){
        Ideas ideas = service.save(ideasDTO);
        return ResponseEntity.status(HttpStatus.CREATED).body(ideas);
    }

    @PutMapping
    public ResponseEntity<IdeasDTO> updateIdeas(@RequestBody IdeasDTO ideasDTO){
        IdeasDTO ideas = service.update(ideasDTO);
        return ResponseEntity.ok(ideas);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteIdeas(@PathVariable Long id){
        service.delete(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/{id}")
    public ResponseEntity<IdeasDTO> getIdeasById(@PathVariable Long id){
        return ResponseEntity.ok(service.findById(id));
    }
}
