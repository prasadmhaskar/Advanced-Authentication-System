package com.pnm.auth.specification;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.entity.UserOAuthProvider;
import com.pnm.auth.dto.request.UserFilterRequest;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.JoinType;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;

public class UserSpecification {

    public static Specification<User> getFilter(UserFilterRequest request) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            // 🚨 CRITICAL: Use DISTINCT to prevent duplicate rows when joining roles/providers
            // Without this, pagination totals will be wrong or queries might fail.
            query.distinct(true);

            // 1. Search (Email or Full Name)
            if (StringUtils.hasText(request.getSearch())) {
                String searchPattern = "%" + request.getSearch().toLowerCase() + "%";
                predicates.add(cb.or(
                        cb.like(cb.lower(root.get("email")), searchPattern),
                        cb.like(cb.lower(root.get("fullName")), searchPattern)
                ));
            }

            // 2. Filter by Role (Join ElementCollection)
            if (StringUtils.hasText(request.getRole())) {
                // "roles" is the name of the List<String> field in User entity
                predicates.add(cb.equal(root.join("roles", JoinType.LEFT), request.getRole()));
            }

            // 3. Filter by Active Status
            if (request.getActive() != null) {
                predicates.add(cb.equal(root.get("active"), request.getActive()));
            }

            // 4. Filter by Provider (Google/Email)
            if (request.getProvider() != null) {
                // "authProviders" is the name of Set<UserOAuthProvider> in User entity
                Join<User, UserOAuthProvider> providerJoin = root.join("authProviders", JoinType.LEFT);
                predicates.add(cb.equal(providerJoin.get("providerType"), request.getProvider()));
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }
}