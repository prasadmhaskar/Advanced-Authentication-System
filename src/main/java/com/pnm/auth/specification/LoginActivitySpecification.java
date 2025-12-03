package com.pnm.auth.specification;

import com.pnm.auth.dto.request.LoginActivityFilterRequest;
import com.pnm.auth.entity.LoginActivity;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;

public class LoginActivitySpecification {

    public static Specification<LoginActivity> filter(LoginActivityFilterRequest filter) {

        return (root, query, builder) -> {

            Predicate predicate = builder.conjunction();

            // filter by email
            if (filter.getEmail() != null && !filter.getEmail().isBlank()) {
                predicate = builder.and(
                        predicate,
                        builder.equal(root.get("email"), filter.getEmail())
                );
            }

            // filter by status
            if (filter.getStatus() != null && !filter.getStatus().isBlank()) {
                predicate = builder.and(
                        predicate,
                        builder.equal(root.get("status"), filter.getStatus())
                );
            }

            // filter by userId
            if (filter.getUserId() != null) {
                predicate = builder.and(
                        predicate,
                        builder.equal(root.get("user").get("id"), filter.getUserId())
                );
            }

            // start date
            if (filter.getStart() != null) {
                predicate = builder.and(
                        predicate,
                        builder.greaterThanOrEqualTo(root.get("createdAt"), filter.getStart())
                );
            }

            // end date
            if (filter.getEnd() != null) {
                predicate = builder.and(
                        predicate,
                        builder.lessThanOrEqualTo(root.get("createdAt"), filter.getEnd())
                );
            }

            return predicate;
        };
    }
}

