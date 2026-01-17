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

    private UserSpecification() {
        throw new UnsupportedOperationException("Utility class cannot be instantiated");
    }

    public static Specification<User> getFilter(UserFilterRequest request) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            assert query != null;
            query.distinct(true);

            // Search (email or full name)
            if (StringUtils.hasText(request.getSearch())) {
                String searchPattern = "%" + request.getSearch().toLowerCase() + "%";
                predicates.add(cb.or(
                        cb.like(cb.lower(root.get("email")), searchPattern),
                        cb.like(cb.lower(root.get("fullName")), searchPattern)
                ));
            }

            // Filter by role
            if (StringUtils.hasText(request.getRole())) {
                predicates.add(cb.equal(root.join("roles", JoinType.LEFT), request.getRole()));
            }

            // Filter by active status
            if (request.getActive() != null) {
                predicates.add(cb.equal(root.get("active"), request.getActive()));
            }

            // Filter by Provider (Google/Email)
            if (request.getProvider() != null) {
                Join<User, UserOAuthProvider> providerJoin = root.join("authProviders", JoinType.LEFT);
                predicates.add(cb.equal(providerJoin.get("providerType"), request.getProvider()));
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }
}