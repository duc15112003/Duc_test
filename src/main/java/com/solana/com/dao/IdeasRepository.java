package com.solana.com.dao;

import com.solana.com.model.Ideas;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IdeasRepository extends JpaRepository<Ideas,Long> {
    Ideas findIdeasById(Long id);
}
