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
public class Ideas {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "title", nullable = false, length = 100)
    private String title;

    @Column(name = "description", nullable = false)
    private String description;

    @Column(name = "status", nullable = false, length = 10)
    private String status;

    @Column(name = "image", nullable = false, length = 255)
    private String image;

    @Column(name = "CreatedAt", nullable = false)
    private LocalDate createdAt;

    @Column(name = "updateAt")
    private LocalDate updateAt;

    @Column(name = "endAt", nullable = false)
    private LocalDate endAt;

    @Column(name = "count_feedback")
    private Long countFeedback;

    @Column(name = "award_for_one_feedback", precision = 18, scale = 8)
    private Long awardForOneFeedback;

    @ManyToOne
    @JoinColumn(name = "username", nullable = false)
    private Account account;

    @OneToMany(mappedBy = "idea")
    private Set<Feedback> feedbacks;

    @OneToMany(mappedBy = "idea")
    private Set<Report> reports;

    @OneToMany(mappedBy = "idea")
    private Set<IdeaCategoryMapping> ideaCategoryMappings;
}
