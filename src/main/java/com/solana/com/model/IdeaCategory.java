package com.solana.com.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.util.Set;

@Entity
@Table
@Data
@NoArgsConstructor
@AllArgsConstructor
public class IdeaCategory {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "name", nullable = false, length = 50)
    private String name;

    @Column(name = "description", nullable = false, length = 255)
    private String description;

    @Column(name = "createAt", nullable = false)
    private LocalDate createAt;

    @Column(name = "deleteAt", nullable = false)
    private LocalDate deleteAt;

    @OneToMany(mappedBy = "category")
    private Set<IdeaCategoryMapping> ideaCategoryMappings;
}
