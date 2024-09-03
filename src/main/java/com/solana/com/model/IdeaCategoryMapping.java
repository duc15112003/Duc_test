package com.solana.com.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table
@Data
@NoArgsConstructor
@AllArgsConstructor
public class IdeaCategoryMapping {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "IdeaID", nullable = false)
    private Ideas idea;

    @ManyToOne
    @JoinColumn(name = "CategoryID", nullable = false)
    private IdeaCategory category;
}
