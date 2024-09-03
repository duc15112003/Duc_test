package com.solana.com.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Entity
@Table
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Report {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "report", columnDefinition = "nvarchar(max)")
    private String report;

    @Column(name = "reply", columnDefinition = "nvarchar(max)")
    private String reply;

    @Column(name = "createAt")
    private LocalDate createAt;

    @Column(name = "replyAt")
    private LocalDate replyAt;

    @Column(name = "status", length = 10)
    private String status;

    @ManyToOne
    @JoinColumn(name = "username")
    private Account account;

    @ManyToOne
    @JoinColumn(name = "id_idea")
    private Ideas idea;

    @ManyToOne
    @JoinColumn(name = "id_feedback")
    private Feedback feedback;


}
