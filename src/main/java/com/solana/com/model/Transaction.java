package com.solana.com.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Entity
@Table(name = "transactions")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Transaction {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "transaction_type", length = 10)
    private String transactionType;

    @Column(name = "description", length = 255)
    private String description;

    @Column(name = "status", length = 10)
    private String status;

    @Column(name = "amount", precision = 18, scale = 8)
    private Long amount;

    @Column(name = "feeTransaction", precision = 18, scale = 8)
    private Long feeTransaction;

    @Column(name = "timestamp")
    private LocalDate timestamp;

    @Column(name = "block_hash", length = 64)
    private String blockHash;

    @ManyToOne
    @JoinColumn(name = "username", nullable = false)
    private Account account;
}
