package com.solana.com.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@Entity
@Table(name = "account")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Account {
    @Id
    @Column(name = "username", nullable = false, length = 50)
    private String username;

    @Column(name = "password", nullable = false, length = 255)
    private String password;

    @ManyToOne
    @JoinColumn(name = "id_user")
    private Users user;

    @ManyToOne
    @JoinColumn(name = "id_admin")
    private Admin admin;

    @OneToMany(mappedBy = "account")
    private Set<RoleMapping> roleMappings;

    @OneToMany(mappedBy = "account")
    private Set<Feedback> feedbacks;

    @OneToMany(mappedBy = "account")
    private Set<Transaction> transactions;
}
