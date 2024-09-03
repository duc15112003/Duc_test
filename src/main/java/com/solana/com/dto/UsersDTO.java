package com.solana.com.dto;

import com.solana.com.model.Account;
import jakarta.persistence.Column;
import jakarta.persistence.OneToMany;
import lombok.*;

import java.time.LocalDate;
import java.util.Set;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UsersDTO {
    private Long id;

    private String firstname;

    private String lastname;

    private String avatar;

    private LocalDate birthday;

    private String address;

    private String phoneNumber;

    private String publicKey;

    private LocalDate createAt;
}
