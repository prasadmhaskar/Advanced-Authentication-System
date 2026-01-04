package com.pnm.auth.specification;

import com.pnm.auth.domain.entity.LoginActivity;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.dto.request.LoginActivityFilterRequest;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.JoinType;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;

public class LoginActivitySpecification {

    public static Specification<LoginActivity> getFilter(LoginActivityFilterRequest request) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            // 1. User ID Filter (The New Feature)
            if (request.getUserId() != null) {
                Join<LoginActivity, User> userJoin = root.join("user", JoinType.LEFT);
                predicates.add(cb.equal(userJoin.get("id"), request.getUserId()));
            }

            // 2. Search (Email or IP)
            if (StringUtils.hasText(request.getSearch())) {
                String pattern = "%" + request.getSearch().toLowerCase() + "%";
                predicates.add(cb.or(
                        cb.like(cb.lower(root.get("email")), pattern),
                        cb.like(cb.lower(root.get("ipAddress")), pattern)
                ));
            }

            // 3. Status Filter
            if (request.getSuccess() != null) {
                String statusValue = request.getSuccess() ? "SUCCESS" : "FAILED";
                predicates.add(cb.equal(root.get("status"), statusValue));
            }

            // 4. Date Range
            if (request.getStartDate() != null) {
                predicates.add(cb.greaterThanOrEqualTo(root.get("createdAt"), request.getStartDate()));
            }
            if (request.getEndDate() != null) {
                predicates.add(cb.lessThanOrEqualTo(root.get("createdAt"), request.getEndDate()));
            }

            query.distinct(true);

            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }
}