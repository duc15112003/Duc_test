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
public class Admin {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "firstname", nullable = false, length = 255)
    private String firstname;

    @Column(name = "lastname", nullable = false, length = 255)
    private String lastname;

    @Column(name = "avatar", nullable = false, length = 255)
    private String avatar;

    @Column(name = "birthday", nullable = false)
    private java.sql.Date birthday;

    @Column(name = "address", length = 255)
    private String address;

    @Column(name = "phone_number", nullable = false, length = 13)
    private String phoneNumber;

    @Column(name = "public_key", length = 255)
    private String publicKey;

    @Column(name = "createAt", nullable = false)
    private LocalDate createAt;

    @OneToMany(mappedBy = "admin")
    private Set<Account> accounts;
}
