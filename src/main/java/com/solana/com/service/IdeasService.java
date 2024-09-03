package com.solana.com.service;

import com.solana.com.dao.AccountRepository;
import com.solana.com.dao.IdeasRepository;
import com.solana.com.dto.IdeasDTO;
import com.solana.com.mapper.IdeasMapper;
import com.solana.com.model.Ideas;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.List;

@Service
public class IdeasService {
    @Autowired
    IdeasRepository ideasRepository;
    @Autowired
    AccountRepository accountRepository;

    // get all Idea
    public List<Ideas> findAll(){
        List<Ideas> list = ideasRepository.findAll();
        return list;
    }
    // save idea
    public Ideas save(IdeasDTO ideasDTO){
        Ideas ideas = IdeasMapper.INSTANCE.toIdeas(ideasDTO);
        return ideasRepository.save(ideas);
    }
    //update idea
    public IdeasDTO update(IdeasDTO ideasDTO){
        Ideas ideas = ideasRepository.findIdeasById(ideasDTO.getId());
        ideas.setAccount(accountRepository.findById(ideasDTO.getAccountUsername()).get());
        ideas.setUpdateAt(LocalDate.now());
        ideas.setCreatedAt(ideasDTO.getCreatedAt());
        ideas.setDescription(ideasDTO.getDescription());
        ideas.setCountFeedback(ideasDTO.getCountFeedback());
        ideas.setAwardForOneFeedback(ideasDTO.getAwardForOneFeedback());
        ideas.setStatus(ideasDTO.getStatus());
        ideas.setTitle(ideasDTO.getTitle());
        return ideasDTO;
    }
    //delete idea
    public Ideas delete(Long id){
        Ideas ideas = ideasRepository.findIdeasById(id);
        ideas.setStatus("INACTIVE");
        return ideasRepository.save(ideas);
    }

    public IdeasDTO findById(Long id){
        Ideas ideas = ideasRepository.findIdeasById(id);
        IdeasDTO ideasDTO = IdeasMapper.INSTANCE.toIdeasDto(ideas);
        return ideasDTO;
    }
}
