package com.solana.com.dao;

import com.solana.com.model.RoleMapping;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Arrays;
import java.util.List;

public interface RoleMappingRepository extends JpaRepository<RoleMapping, Long> {
    @Query("select r from RoleMapping r where r.account.username =?1")
    List<RoleMapping> findByUsername(String username);
}
