package com.solana.com.dto;

import lombok.*;

import java.time.LocalDate;
import java.util.Set;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class IdeasDTO {
    private Long id;
    private String title;
    private String description;
    private String status;
    private String image;
    private LocalDate createdAt;
    private LocalDate updateAt;
    private LocalDate endAt;
    private Long countFeedback;
    private Long awardForOneFeedback;
    private String accountUsername; // Assuming account has a username field
    private Set<Long> feedbackIds; // Assuming Feedback has an id field
    private Set<Long> reportIds; // Assuming Report has an id field
    private Set<Long> ideaCategoryMappingIds; // Assuming IdeaCategoryMapping has an id field
}
